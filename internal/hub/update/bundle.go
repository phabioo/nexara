package update

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"

	"github.com/phabioo/nexara/internal/release"
)

// Sizes. They bound what the hub downloads or accepts as an upload, and what
// the root helper reads from the hub-owned directory.
const (
	MaxDebBytes     = 256 << 20
	MaxSumsBytes    = 64 << 10
	MaxRequestBytes = 8 << 10
	MaxResultBytes  = 96 << 10
	// MaxBundleBytes bounds a whole upload (tar or multipart): the package
	// plus headers and the two small signature files.
	MaxBundleBytes = MaxDebBytes + 1<<20
)

// maxDeb is MaxDebBytes; tests lower it to exercise the limit without
// handling hundreds of megabytes.
var maxDeb int64 = MaxDebBytes

// Names of the release files that make up a bundle.
const (
	SumsFile = "SHA256SUMS"
	SigFile  = "SHA256SUMS.sig"
)

// Errors returned by staging and installing. They wrap more detail; test with
// errors.Is.
var (
	ErrBadSignature     = errors.New("update: signature check failed")
	ErrChecksum         = errors.New("update: checksum check failed")
	ErrBadBundle        = errors.New("update: invalid update bundle")
	ErrTooLarge         = errors.New("update: file is too large")
	ErrWrongArch        = errors.New("update: package is for another architecture")
	ErrDowngrade        = errors.New("update: package is older than the running version")
	ErrAlreadyInstalled = errors.New("update: this version is already installed")
	ErrDevBuild         = errors.New("update: a development build cannot be updated")
	ErrCheckDisabled    = errors.New("update: the GitHub update check is turned off")
	ErrBusy             = errors.New("update: an update is already in progress")
	ErrNotStaged        = errors.New("update: no such staged update")
	ErrUnsupported      = errors.New("update: the update helper does not watch this data directory")
	ErrNoUpdate         = errors.New("update: no newer release is available")
	ErrNoRequest        = errors.New("update: no update request pending")
)

var debNameRe = regexp.MustCompile(`^nexus_(` + versionPattern + `)_(arm64|amd64)\.deb$`)

// DebName is the file name of the hub package, as scripts/package-deb.sh
// writes it: nexus_<version>_<arch>.deb.
func DebName(version, arch string) string { return "nexus_" + version + "_" + arch + ".deb" }

// ParseDebName extracts version and architecture from a package file name.
func ParseDebName(name string) (Version, string, error) {
	m := debNameRe.FindStringSubmatch(name)
	if m == nil {
		return Version{}, "", fmt.Errorf("%w: %q is not a nexus_<version>_<arch>.deb file name", ErrBadBundle, name)
	}
	v, err := ParseVersion(m[1])
	if err != nil {
		return Version{}, "", fmt.Errorf("%w: %v", ErrBadBundle, err)
	}
	return v, m[2], nil
}

// HostArch is the package architecture of this machine.
func HostArch() (string, error) {
	switch runtime.GOARCH {
	case "arm64", "amd64":
		return runtime.GOARCH, nil
	}
	return "", fmt.Errorf("update: unsupported architecture %s", runtime.GOARCH)
}

// checkPolicy decides whether a package may replace the running version. The
// current version of a development build is not comparable.
func checkPolicy(debName, arch, current string, allowDowngrade bool) (Version, error) {
	v, debArch, err := ParseDebName(debName)
	if err != nil {
		return Version{}, err
	}
	if debArch != arch {
		return Version{}, fmt.Errorf("%w: package is %s, this machine is %s", ErrWrongArch, debArch, arch)
	}
	cur, err := ParseVersion(current)
	if err != nil {
		if allowDowngrade {
			return v, nil
		}
		return Version{}, fmt.Errorf("%w (version %q)", ErrDevBuild, current)
	}
	switch c := v.Compare(cur); {
	case c == 0 && !allowDowngrade:
		return Version{}, fmt.Errorf("%w (%s)", ErrAlreadyInstalled, cur)
	case c < 0 && !allowDowngrade:
		return Version{}, fmt.Errorf("%w: %s < %s", ErrDowngrade, v, cur)
	}
	return v, nil
}

// verifyMeta checks the signature over sums and returns the digest sums lists
// for debName. key defaults to the embedded release key.
func verifyMeta(key ed25519.PublicKey, sums, sig []byte, debName string) (string, error) {
	if key == nil {
		key = release.PublicKey()
	}
	if err := release.VerifySumsWithKey(key, sums, sig); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	entries, err := release.ParseSums(sums)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadBundle, err)
	}
	digest, ok := entries[debName]
	if !ok {
		return "", fmt.Errorf("%w: %s is not listed in %s", ErrBadBundle, debName, SumsFile)
	}
	return digest, nil
}

// verifyDeb hashes the package and compares it with the signed sums.
func verifyDeb(sums []byte, debName string, r io.Reader) error {
	if err := release.CheckFile(sums, debName, r); err != nil {
		return fmt.Errorf("%w: %v", ErrChecksum, err)
	}
	return nil
}
