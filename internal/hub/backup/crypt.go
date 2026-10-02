package backup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/phabioo/nexara/internal/hub/auth"
)

// Envelope constants. See the package documentation for the byte layout.
const (
	envelopeMagic   = "NXBKUP"
	envelopeVersion = 1

	// kdfPassphrase: key = argon2id(passphrase, salt). kdfLocal: key =
	// HKDF-SHA-256(secret.key, salt, hkdfInfoLocal).
	kdfPassphrase byte = 1
	kdfLocal      byte = 2

	chunkLog2   = 16
	chunkSize   = 1 << chunkLog2
	tagSize     = 16
	saltSize    = 16
	prefixSize  = 7
	headerSize  = len(envelopeMagic) + 1 + 1 + 1 + 4 + 4 + 1 + saltSize + prefixSize
	hkdfInfoLoc = "nexus/v1 local-backup-aes-gcm"

	// Upper bounds for the KDF parameters read from a (possibly hostile) file.
	maxKDFMemoryKiB = 512 * 1024
	maxKDFTime      = 16
	maxKDFThreads   = 16
)

// Errors of the envelope. They are deliberately few and readable: the UI
// shows them as they are.
var (
	// ErrNotBackup means the data is not a Nexara backup file.
	ErrNotBackup = errors.New("backup: this is not a Nexara backup file")
	// ErrUnsupportedFormat means the file was written by a newer format version.
	ErrUnsupportedFormat = errors.New("backup: the backup format is newer than this Nexus understands")
	// ErrAuth means the first chunk did not open: wrong passphrase, or the
	// file is damaged at its start. The two cannot be told apart.
	ErrAuth = errors.New("backup: wrong passphrase, or the file is damaged")
	// ErrCorrupt means a later chunk failed authentication or the file was
	// cut short, reordered or extended.
	ErrCorrupt = errors.New("backup: the file is damaged or has been modified")
	// ErrWrongKeyKind means a local backup was opened with a passphrase or
	// the other way round.
	ErrWrongKeyKind = errors.New("backup: the file is encrypted with a different kind of key")
)

// KDFParams are the argon2id cost parameters of a passphrase backup. They are
// stored in the file header, so they can be raised later without breaking old
// backups.
type KDFParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultKDF is sized for a Raspberry Pi: 128 MiB, 3 passes, 2 lanes (roughly
// a second on a Pi 5). A disaster copy that leaves the device deserves more
// than a login hash.
var DefaultKDF = KDFParams{Time: 3, MemoryKiB: 128 * 1024, Threads: 2}

func (p KDFParams) validate() error {
	switch {
	case p.Threads < 1 || p.Threads > maxKDFThreads:
		return errors.New("backup: argon2 threads out of range")
	case p.Time < 1 || p.Time > maxKDFTime:
		return errors.New("backup: argon2 time out of range")
	case p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxKDFMemoryKiB:
		return errors.New("backup: argon2 memory out of range")
	}
	return nil
}

// Key says how a backup file is encrypted. Create one with PassphraseKey or
// LocalKey; the zero Key is invalid.
type Key struct {
	kind       byte
	passphrase []byte
	secret     []byte
	kdf        KDFParams
}

// PassphraseKey is the key of a downloadable backup. The passphrase is not
// validated here (Service.WriteDownload enforces the policy when creating;
// restoring must accept whatever was used).
func PassphraseKey(passphrase string, kdf KDFParams) Key {
	return Key{kind: kdfPassphrase, passphrase: []byte(passphrase), kdf: kdf}
}

// LocalKey is the key of an automatic local backup: derived from secret.key,
// so it has the same protection as the data it protects.
func LocalKey(secret []byte) Key {
	return Key{kind: kdfLocal, secret: bytes.Clone(secret)}
}

// ValidatePassphrase applies the operator passphrase policy (at least 12
// characters) to a backup passphrase.
func ValidatePassphrase(p string) error {
	if !utf8.ValidString(p) {
		return fmt.Errorf("%w: not valid UTF-8", auth.ErrWeakPassphrase)
	}
	return auth.ValidatePassphrase(p)
}

func (k Key) derive(salt []byte, kdf KDFParams) ([]byte, error) {
	switch k.kind {
	case kdfPassphrase:
		if len(k.passphrase) == 0 {
			return nil, errors.New("backup: passphrase is empty")
		}
		if err := kdf.validate(); err != nil {
			return nil, err
		}
		return argon2.IDKey(k.passphrase, salt, kdf.Time, kdf.MemoryKiB, kdf.Threads, 32), nil
	case kdfLocal:
		if len(k.secret) != auth.SecretKeyLen {
			return nil, errors.New("backup: secret key must be 32 bytes")
		}
		return hkdf.Key(sha256.New, k.secret, salt, hkdfInfoLoc, 32)
	default:
		return nil, errors.New("backup: no key given")
	}
}

// header is the plain, authenticated start of every backup file.
type header struct {
	kdf    byte
	params KDFParams
	salt   [saltSize]byte
	prefix [prefixSize]byte
}

func (h header) marshal() []byte {
	b := make([]byte, 0, headerSize)
	b = append(b, envelopeMagic...)
	b = append(b, envelopeVersion, h.kdf, chunkLog2)
	b = binary.BigEndian.AppendUint32(b, h.params.Time)
	b = binary.BigEndian.AppendUint32(b, h.params.MemoryKiB)
	b = append(b, h.params.Threads)
	b = append(b, h.salt[:]...)
	b = append(b, h.prefix[:]...)
	return b
}

func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) != headerSize || string(b[:len(envelopeMagic)]) != envelopeMagic {
		return h, ErrNotBackup
	}
	b = b[len(envelopeMagic):]
	if b[0] > envelopeVersion {
		return h, ErrUnsupportedFormat
	}
	if b[0] != envelopeVersion || b[2] != chunkLog2 || (b[1] != kdfPassphrase && b[1] != kdfLocal) {
		return h, ErrNotBackup
	}
	h.kdf = b[1]
	h.params = KDFParams{
		Time:      binary.BigEndian.Uint32(b[3:7]),
		MemoryKiB: binary.BigEndian.Uint32(b[7:11]),
		Threads:   b[11],
	}
	copy(h.salt[:], b[12:12+saltSize])
	copy(h.prefix[:], b[12+saltSize:])
	return h, nil
}

// readHeader reads and parses the header from r.
func readHeader(r io.Reader) (header, []byte, error) {
	raw := make([]byte, headerSize)
	if _, err := io.ReadFull(r, raw); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return header{}, nil, ErrNotBackup
		}
		return header{}, nil, err
	}
	h, err := parseHeader(raw)
	return h, raw, err
}

// KindOf reports how the backup in r is encrypted, reading only its header:
// "passphrase" or "local".
func KindOf(r io.Reader) (string, error) {
	h, _, err := readHeader(r)
	if err != nil {
		return "", err
	}
	if h.kdf == kdfLocal {
		return "local", nil
	}
	return "passphrase", nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// nonce builds the STREAM nonce: 7-byte random prefix, 32-bit chunk counter,
// 1 byte that is 1 for the final chunk. A truncated file therefore fails
// authentication (its last chunk was sealed as "not last") and so does an
// extended one (the old last chunk is now followed by more data).
func nonce(prefix [prefixSize]byte, ctr uint32, last bool) []byte {
	n := make([]byte, 0, 12)
	n = append(n, prefix[:]...)
	n = binary.BigEndian.AppendUint32(n, ctr)
	if last {
		return append(n, 1)
	}
	return append(n, 0)
}

type encWriter struct {
	w    io.Writer
	aead cipher.AEAD
	hdr  []byte
	pre  [prefixSize]byte
	buf  []byte
	n    int
	ctr  uint32
	out  []byte
	err  error
	done bool
}

// Encrypt writes the file header to w and returns a writer that encrypts what
// is written to it in 64 KiB chunks. Close writes the final chunk; it does not
// close w. Key derivation (argon2id for passphrases) happens here, before the
// first byte reaches w.
func Encrypt(w io.Writer, k Key) (io.WriteCloser, error) {
	h := header{kdf: k.kind, params: k.kdf}
	if k.kind == kdfLocal {
		h.params = KDFParams{}
	}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return nil, fmt.Errorf("backup: random salt: %w", err)
	}
	if _, err := rand.Read(h.prefix[:]); err != nil {
		return nil, fmt.Errorf("backup: random nonce prefix: %w", err)
	}
	key, err := k.derive(h.salt[:], h.params)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	hdr := h.marshal()
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead, hdr: hdr, pre: h.prefix,
		buf: make([]byte, chunkSize), out: make([]byte, 0, chunkSize+tagSize)}, nil
}

func (e *encWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.done {
		return 0, errors.New("backup: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		// A full buffer is only sealed once more data follows, so the final
		// chunk is always known when it is written.
		if e.n == chunkSize {
			if err := e.seal(false); err != nil {
				return total - len(p), err
			}
		}
		c := copy(e.buf[e.n:], p)
		e.n += c
		p = p[c:]
	}
	return total, nil
}

func (e *encWriter) seal(last bool) error {
	if e.ctr == ^uint32(0) {
		e.err = errors.New("backup: too many chunks")
		return e.err
	}
	e.out = e.aead.Seal(e.out[:0], nonce(e.pre, e.ctr, last), e.buf[:e.n], e.hdr)
	if _, err := e.w.Write(e.out); err != nil {
		e.err = err
		return err
	}
	e.ctr++
	e.n = 0
	return nil
}

// Close seals the final chunk.
func (e *encWriter) Close() error {
	if e.err != nil {
		return e.err
	}
	if e.done {
		return nil
	}
	e.done = true
	return e.seal(true)
}

type decReader struct {
	br    *bufio.Reader
	aead  cipher.AEAD
	hdr   []byte
	pre   [prefixSize]byte
	ct    []byte
	plain []byte
	pos   int
	ctr   uint32
	done  bool
	err   error
}

// Decrypt reads the header from r and returns a reader that yields the
// plaintext. Every chunk is authenticated before any of its bytes are
// returned, and reading to EOF proves the file is complete: a reader that
// stops early has not verified the tail. The key must match the kind of the
// file (ErrWrongKeyKind otherwise).
func Decrypt(r io.Reader, k Key) (io.Reader, error) {
	br := bufio.NewReaderSize(r, chunkSize+tagSize+1)
	h, raw, err := readHeader(br)
	if err != nil {
		return nil, err
	}
	if h.kdf != k.kind {
		return nil, ErrWrongKeyKind
	}
	key, err := k.derive(h.salt[:], h.params)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &decReader{br: br, aead: aead, hdr: raw, pre: h.prefix, ct: make([]byte, chunkSize+tagSize)}, nil
}

func (d *decReader) Read(p []byte) (int, error) {
	for d.pos >= len(d.plain) {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		d.next()
	}
	n := copy(p, d.plain[d.pos:])
	d.pos += n
	return n, nil
}

func (d *decReader) next() {
	n, err := io.ReadFull(d.br, d.ct)
	last := false
	switch {
	case err == nil:
		if _, perr := d.br.Peek(1); perr == io.EOF {
			last = true
		} else if perr != nil {
			d.err = perr
			return
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		last = true
	case errors.Is(err, io.EOF):
		// No chunk at all, or a stream that ended where a chunk was due.
		d.err = d.failure()
		return
	default:
		d.err = err
		return
	}
	pt, err := d.aead.Open(d.plain[:0], nonce(d.pre, d.ctr, last), d.ct[:n], d.hdr)
	if err != nil {
		d.err = d.failure()
		return
	}
	d.plain, d.pos = pt, 0
	d.ctr++
	d.done = last
}

func (d *decReader) failure() error {
	if d.ctr == 0 {
		return ErrAuth
	}
	return ErrCorrupt
}
