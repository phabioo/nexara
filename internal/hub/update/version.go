package update

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionPattern is the accepted release version: semantic versioning with an
// optional pre-release part ("0.2.0", "0.2.0-rc1") and no build metadata. The
// character set is restricted on purpose: a version becomes a directory and a
// file name, so it can never contain a path separator.
const versionPattern = `(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]{1,32}(?:\.[0-9A-Za-z-]{1,32}){0,5})?`

var versionRe = regexp.MustCompile(`^v?(` + versionPattern + `)$`)

// Version is a parsed release version.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string // pre-release identifiers; empty for a release
	text                string
}

// ParseVersion parses "0.2.0", "v0.2.0" or "0.2.0-rc1".
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("update: %q is not a release version", s)
	}
	core, pre, _ := strings.Cut(m[1], "-")
	var v Version
	nums := strings.Split(core, ".")
	for i, dst := range []*uint64{&v.Major, &v.Minor, &v.Patch} {
		n, err := strconv.ParseUint(nums[i], 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("update: %q is not a release version", s)
		}
		*dst = n
	}
	if pre != "" {
		v.Pre = strings.Split(pre, ".")
	}
	v.text = m[1]
	return v, nil
}

// String returns the version without a "v" prefix.
func (v Version) String() string { return v.text }

// IsPrerelease reports whether v has a pre-release part.
func (v Version) IsPrerelease() bool { return len(v.Pre) > 0 }

// Compare orders versions by semantic versioning precedence: -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, p := range [][2]uint64{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if c := cmpUint(p[0], p[1]); c != 0 {
			return c
		}
	}
	switch {
	case len(v.Pre) == 0 && len(o.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1 // a release is newer than its pre-releases
	case len(o.Pre) == 0:
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		if c := cmpIdent(v.Pre[i], o.Pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(v.Pre)), uint64(len(o.Pre)))
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpIdent compares pre-release identifiers: numeric ones numerically and
// below alphanumeric ones, alphanumeric ones lexically.
func cmpIdent(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 64)
	bn, berr := strconv.ParseUint(b, 10, 64)
	switch {
	case aerr == nil && berr == nil:
		return cmpUint(an, bn)
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// normalizeVersion strips a "v" prefix for comparing version strings that
// are not parsed (the admin socket answer).
func normalizeVersion(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "v") }
