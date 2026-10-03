package backup

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// writeArchive writes the tar stream: manifest.json first (so a listing only
// has to decrypt the first chunks), then every file named in m from stage.
func writeArchive(w io.Writer, stage string, m Manifest) error {
	tw := tar.NewWriter(w)
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: nameManifest, Mode: 0o600, Size: int64(len(mb)), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(mb); err != nil {
		return err
	}
	for _, f := range m.Files {
		if err := copyMember(tw, stage, f, m); err != nil {
			return err
		}
	}
	return tw.Close()
}

func copyMember(tw *tar.Writer, stage string, f FileEntry, m Manifest) error {
	src, err := os.Open(filepath.Join(stage, filepath.FromSlash(f.Name)))
	if err != nil {
		return err
	}
	defer src.Close()
	if err := tw.WriteHeader(&tar.Header{Name: f.Name, Mode: 0o600, Size: f.Size, ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	n, err := io.Copy(tw, src)
	if err != nil {
		return err
	}
	if n != f.Size {
		return fmt.Errorf("backup: %s changed while it was being written", f.Name)
	}
	return nil
}

// MaxArchiveBytes caps the sum of the member sizes a backup may declare (and
// the decrypted stream). Twice the setup wizard's upload limit: the archive is
// the database, keys and certificates, tens of megabytes in practice.
const MaxArchiveBytes int64 = 1 << 30

// archiveLimit is MaxArchiveBytes; tests lower it.
var archiveLimit = MaxArchiveBytes

var errTooLarge = errors.New("backup: the backup is larger than this Nexus restores")

// readMode says how much readArchive does with the members.
type readMode int

const (
	readManifestOnly readMode = iota // stop after the manifest (listings)
	readVerify                       // read everything, check hashes, keep nothing
	readExtract                      // as readVerify, writing the files below dest
)

// readArchive reads an archive from the decrypted stream r. Whatever the mode,
// it never trusts names or sizes of the tar: members must be listed in the
// manifest, regular, and of the listed size. In the verifying modes it reads
// r to its end, which is what authenticates the last chunk of the envelope.
func readArchive(r io.Reader, mode readMode, dest string) (Manifest, error) {
	// The decrypted stream is as long as the members plus tar framing; a
	// longer one is not an archive this Nexus wrote (the sum of the member
	// sizes is checked below, once the manifest is known).
	r = io.LimitReader(r, archiveLimit+2*maxManifestSize)
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	if err != nil {
		return Manifest{}, archiveErr(err)
	}
	if hdr.Name != nameManifest || hdr.Typeflag != tar.TypeReg || hdr.Size > maxManifestSize || len(hdr.PAXRecords) > 0 {
		return Manifest{}, errors.New("backup: this archive does not start with a manifest")
	}
	mb, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
	if err != nil {
		return Manifest{}, archiveErr(err)
	}
	m, err := parseManifest(mb)
	if err != nil {
		return m, err
	}
	if m.Format > ArchiveVersion {
		return m, fmt.Errorf("%w (archive format %d, this Nexus reads up to %d)", ErrUnsupportedFormat, m.Format, ArchiveVersion)
	}
	if err := m.validate(); err != nil {
		return m, err
	}
	if mode == readManifestOnly {
		return m, nil
	}
	var total int64
	for _, f := range m.Files {
		if f.Size > archiveLimit {
			return m, errTooLarge
		}
		total += f.Size
	}
	if total > archiveLimit {
		return m, errTooLarge
	}

	want := make(map[string]FileEntry, len(m.Files))
	for _, f := range m.Files {
		want[f.Name] = f
	}
	for len(want) > 0 {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, archiveErr(err)
		}
		f, ok := want[hdr.Name]
		// PAX records can carry sparse maps: a few KB on the wire that expand
		// to gigabytes on disk. This Nexus writes plain ustar headers only.
		if !ok || hdr.Typeflag != tar.TypeReg || len(hdr.PAXRecords) > 0 {
			return m, fmt.Errorf("backup: unexpected archive member %q", sanitize(hdr.Name))
		}
		if hdr.Size != f.Size {
			return m, fmt.Errorf("backup: %s has the wrong size", f.Name)
		}
		delete(want, f.Name)
		if err := checkMember(tr, f, mode, dest); err != nil {
			return m, err
		}
	}
	if len(want) > 0 {
		return m, errors.New("backup: the archive is incomplete")
	}
	// Anything after the last member (tar padding is fine) must be padding;
	// reading to the end also makes the envelope check its final chunk.
	if _, err := tr.Next(); err != io.EOF {
		if err == nil {
			return m, errors.New("backup: the archive has unexpected extra members")
		}
		return m, archiveErr(err)
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return m, archiveErr(err)
	}
	return m, nil
}

// checkMember streams one member through SHA-256 (and into dest) and compares
// with the manifest.
func checkMember(r io.Reader, f FileEntry, mode readMode, dest string) (err error) {
	h := sha256.New()
	var w io.Writer = h
	if mode == readExtract {
		path := filepath.Join(dest, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}()
		w = io.MultiWriter(h, out)
	}
	n, err := io.Copy(w, io.LimitReader(r, f.Size+1))
	if err != nil {
		return archiveErr(err)
	}
	if n != f.Size {
		return fmt.Errorf("backup: %s is truncated", f.Name)
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(f.SHA256) {
		return fmt.Errorf("backup: %s does not match its checksum", f.Name)
	}
	return nil
}

// archiveErr keeps the envelope's readable errors and turns tar's own
// "unexpected EOF" into the same message.
func archiveErr(err error) error {
	switch {
	case errors.Is(err, ErrAuth), errors.Is(err, ErrCorrupt):
		return err
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return ErrCorrupt
	}
	return fmt.Errorf("backup: unreadable archive: %w", err)
}

func sanitize(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
