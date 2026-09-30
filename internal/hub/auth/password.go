package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Passphrase policy.
const (
	MinPassphraseLength = 12   // runes
	MaxPassphraseLength = 1024 // runes; bounds the work an attacker can make us hash
)

// HashParams are the argon2id cost parameters. Memory is in KiB.
type HashParams struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultHashParams is sized for a Raspberry Pi 4/5: 64 MiB, 3 passes, 2
// lanes (about 0.3-0.5 s per hash on a Pi 5). That is the OWASP
// "t=3, m=64 MiB" recommendation; the hub serialises hashing so at most a
// couple of 64 MiB buffers exist at once.
var DefaultHashParams = HashParams{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}

// Bounds applied when parsing stored hashes, so a corrupted or tampered
// database row cannot make us allocate gigabytes.
const (
	maxParseMemoryKiB = 1 << 20 // 1 GiB
	maxParseTime      = 64
	maxParseThreads   = 64
	minSaltLen        = 8
	minKeyLen         = 16
	maxKeyLen         = 1024
)

func (p HashParams) validate() error {
	switch {
	case p.Memory < 8*uint32(max(p.Threads, 1)) || p.Memory > maxParseMemoryKiB:
		return errors.New("auth: argon2 memory out of range")
	case p.Time < 1 || p.Time > maxParseTime:
		return errors.New("auth: argon2 time out of range")
	case p.Threads < 1 || p.Threads > maxParseThreads:
		return errors.New("auth: argon2 threads out of range")
	case p.KeyLen < minKeyLen || p.KeyLen > maxKeyLen:
		return errors.New("auth: argon2 key length out of range")
	case p.SaltLen < minSaltLen:
		return errors.New("auth: argon2 salt too short")
	}
	return nil
}

var b64 = base64.RawStdEncoding

// HashPassword returns the PHC-style encoding
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash> (unpadded standard base64).
// It does not apply the passphrase policy; see ValidatePassphrase.
func HashPassword(pass string, p HashParams) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read random salt: %w", err)
	}
	key := argon2.IDKey([]byte(pass), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type parsedHash struct {
	params HashParams
	salt   []byte
	key    []byte
}

func parseHash(encoded string) (parsedHash, error) {
	bad := errors.New("auth: malformed password hash")
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return parsedHash{}, bad
	}
	ver, ok := strings.CutPrefix(parts[2], "v=")
	if v, err := strconv.Atoi(ver); !ok || err != nil || v != argon2.Version {
		return parsedHash{}, bad
	}
	var ph parsedHash
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil {
			return parsedHash{}, bad
		}
		switch k {
		case "m":
			ph.params.Memory = uint32(n)
		case "t":
			ph.params.Time = uint32(n)
		case "p":
			if n > 255 {
				return parsedHash{}, bad
			}
			ph.params.Threads = uint8(n)
		default:
			return parsedHash{}, bad
		}
	}
	var err error
	if ph.salt, err = b64.DecodeString(parts[4]); err != nil {
		return parsedHash{}, bad
	}
	if ph.key, err = b64.DecodeString(parts[5]); err != nil {
		return parsedHash{}, bad
	}
	ph.params.SaltLen, ph.params.KeyLen = uint32(len(ph.salt)), uint32(len(ph.key))
	if ph.params.validate() != nil {
		return parsedHash{}, bad
	}
	return ph, nil
}

// VerifyPassword checks pass against an encoded hash in constant time. The
// error is non-nil only if the stored hash is malformed (never for a wrong
// passphrase).
func VerifyPassword(pass, encoded string) (bool, error) {
	ph, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(pass), ph.salt, ph.params.Time, ph.params.Memory, ph.params.Threads, ph.params.KeyLen)
	return subtle.ConstantTimeCompare(key, ph.key) == 1, nil
}

// NeedsRehash reports whether encoded was made with parameters different
// from want (or cannot be parsed), so it should be re-hashed after a
// successful login.
func NeedsRehash(encoded string, want HashParams) bool {
	ph, err := parseHash(encoded)
	if err != nil {
		return true
	}
	return ph.params != want
}

// ValidatePassphrase enforces the length policy (12 to 1024 characters).
// The error wraps ErrWeakPassphrase. There are no composition rules on
// purpose: length is what matters.
func ValidatePassphrase(pass string) error {
	n := utf8.RuneCountInString(pass)
	switch {
	case !utf8.ValidString(pass):
		return fmt.Errorf("%w: not valid UTF-8", ErrWeakPassphrase)
	case n < MinPassphraseLength:
		return fmt.Errorf("%w: at least %d characters required", ErrWeakPassphrase, MinPassphraseLength)
	case n > MaxPassphraseLength:
		return fmt.Errorf("%w: at most %d characters allowed", ErrWeakPassphrase, MaxPassphraseLength)
	}
	return nil
}

// Strength scores a passphrase from 0 to 5 for the setup wizard's
// 5-segment meter. It is advisory; ValidatePassphrase is the gate.
//
//	length points: <8 runes: 0, 8-11: 1, 12-15: 2, 16-23: 3, >=24: 4
//	variety point: +1 if at least three character classes are used
//	               (lower, upper, digit, other such as space/symbol/non-ASCII letter)
//	penalty:       fewer than 5 distinct characters caps the score at 1
//
// The empty string scores 0 and the result is capped at 5. So a 12-character
// lower-case string shows 2 segments, a 16-character passphrase of words 3,
// and 24+ characters with mixed classes fills the meter.
func Strength(pass string) int {
	n := utf8.RuneCountInString(pass)
	if n == 0 {
		return 0
	}
	var score int
	switch {
	case n >= 24:
		score = 4
	case n >= 16:
		score = 3
	case n >= 12:
		score = 2
	case n >= 8:
		score = 1
	}
	var lower, upper, digit, other bool
	distinct := map[rune]struct{}{}
	for _, r := range pass {
		distinct[r] = struct{}{}
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		case unicode.IsControl(r):
			// control characters add no variety
		default:
			other = true
		}
	}
	classes := 0
	for _, c := range []bool{lower, upper, digit, other} {
		if c {
			classes++
		}
	}
	if classes >= 3 {
		score++
	}
	if len(distinct) < 5 && score > 1 {
		score = 1
	}
	return min(score, 5)
}
