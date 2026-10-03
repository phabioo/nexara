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
// below alphanumeric ones; alphanumeric ones like dpkg does, digit runs by
// value, so that rc2 < rc10 (a plain string comparison would refuse the
// update from rc2 to rc10 as a downgrade).
func cmpIdent(a, b string) int {
	an, bn := allDigits(a), allDigits(b)
	switch {
	case an && !bn:
		return -1
	case !an && bn:
		return 1
	}
	return cmpDpkg(a, b)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// dpkgOrder is dpkg's weight of a non-digit character: letters sort before
// everything else, "~" before even the end of the string.
func dpkgOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// cmpDpkg is dpkg's verrevcmp: alternating runs of non-digits (by weight) and
// digits (by value, without overflow).
func cmpDpkg(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		for (len(a) > 0 && !isDigit(a[0])) || (len(b) > 0 && !isDigit(b[0])) {
			var ac, bc int
			if len(a) > 0 {
				ac = dpkgOrder(a[0])
			}
			if len(b) > 0 {
				bc = dpkgOrder(b[0])
			}
			if ac != bc {
				return cmpUint(uint64(ac+1), uint64(bc+1))
			}
			if len(a) > 0 {
				a = a[1:]
			}
			if len(b) > 0 {
				b = b[1:]
			}
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		diff := 0
		for len(a) > 0 && len(b) > 0 && isDigit(a[0]) && isDigit(b[0]) {
			if diff == 0 {
				diff = int(a[0]) - int(b[0])
			}
			a, b = a[1:], b[1:]
		}
		switch {
		case len(a) > 0 && isDigit(a[0]):
			return 1
		case len(b) > 0 && isDigit(b[0]):
			return -1
		case diff != 0:
			return cmpUint(uint64(diff+256), 256)
		}
	}
	return 0
}

// normalizeVersion strips a "v" prefix for comparing version strings that
// are not parsed (the admin socket answer).
func normalizeVersion(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "v") }
