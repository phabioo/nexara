package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	enc, err := HashPassword(testPass, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") || strings.Count(enc, "$") != 5 {
		t.Fatalf("unexpected encoding %q", enc)
	}
	enc2, _ := HashPassword(testPass, testParams)
	if enc == enc2 {
		t.Fatal("two hashes of the same passphrase must differ (random salt)")
	}

	tests := []struct {
		name    string
		pass    string
		encoded string
		wantOK  bool
		wantErr bool
	}{
		{"correct", testPass, enc, true, false},
		{"wrong", testPass + "x", enc, false, false},
		{"empty", "", enc, false, false},
		{"unicode", "pässwörd-mit-ümläuten", mustHash(t, "pässwörd-mit-ümläuten"), true, false},
		{"garbage", testPass, "not a hash", false, true},
		{"wrong algorithm", testPass, strings.Replace(enc, "argon2id", "argon2i", 1), false, true},
		{"wrong version", testPass, strings.Replace(enc, "v=19", "v=16", 1), false, true},
		{"bad base64", testPass, enc[:len(enc)-2] + "!!", false, true},
		{"huge memory rejected", testPass, strings.Replace(enc, "m=64", "m=4000000000", 1), false, true},
		{"zero time rejected", testPass, strings.Replace(enc, "t=1", "t=0", 1), false, true},
		{"unknown param", testPass, strings.Replace(enc, "p=1", "x=1", 1), false, true},
		{"empty string", testPass, "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifyPassword(tc.pass, tc.encoded)
			if ok != tc.wantOK || (err != nil) != tc.wantErr {
				t.Fatalf("VerifyPassword = %v, %v; want ok=%v err=%v", ok, err, tc.wantOK, tc.wantErr)
			}
		})
	}
}

func mustHash(t *testing.T, pass string) string {
	t.Helper()
	enc, err := HashPassword(pass, testParams)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestHashRejectsBadParams(t *testing.T) {
	tests := []struct {
		name string
		p    HashParams
	}{
		{"zero", HashParams{}},
		{"low memory", HashParams{Memory: 4, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}},
		{"no time", HashParams{Memory: 64, Time: 0, Threads: 1, KeyLen: 32, SaltLen: 16}},
		{"short salt", HashParams{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 4}},
		{"short key", HashParams{Memory: 64, Time: 1, Threads: 1, KeyLen: 8, SaltLen: 16}},
	}
	for _, tc := range tests {
		if _, err := HashPassword("x", tc.p); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
	if err := DefaultHashParams.validate(); err != nil {
		t.Fatalf("default params invalid: %v", err)
	}
}

func TestNeedsRehash(t *testing.T) {
	enc := mustHash(t, testPass)
	other := testParams
	other.Time = 2
	bigger := testParams
	bigger.Memory = 128
	threads := HashParams{Memory: 64, Time: 1, Threads: 2, KeyLen: 32, SaltLen: 16}
	key := testParams
	key.KeyLen = 64
	tests := []struct {
		name    string
		encoded string
		want    HashParams
		rehash  bool
	}{
		{"same params", enc, testParams, false},
		{"time changed", enc, other, true},
		{"memory changed", enc, bigger, true},
		{"threads changed", enc, threads, true},
		{"key length changed", enc, key, true},
		{"malformed", "garbage", testParams, true},
	}
	for _, tc := range tests {
		if got := NeedsRehash(tc.encoded, tc.want); got != tc.rehash {
			t.Errorf("%s: NeedsRehash = %v, want %v", tc.name, got, tc.rehash)
		}
	}
}

func TestValidatePassphrase(t *testing.T) {
	tests := []struct {
		name string
		pass string
		ok   bool
	}{
		{"empty", "", false},
		{"11 chars", strings.Repeat("a", 11), false},
		{"12 chars", strings.Repeat("a", 12), true},
		{"12 runes multibyte", strings.Repeat("ä", 12), true},
		{"11 runes multibyte (22 bytes)", strings.Repeat("ä", 11), false},
		{"1024 runes", strings.Repeat("a", 1024), true},
		{"1025 runes", strings.Repeat("a", 1025), false},
		{"invalid utf8", strings.Repeat("a", 12) + "\xff", false},
		{"spaces allowed", "four words with spaces", true},
	}
	for _, tc := range tests {
		err := ValidatePassphrase(tc.pass)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("%s: error does not wrap ErrWeakPassphrase: %v", tc.name, err)
		}
	}
}

func TestStrength(t *testing.T) {
	tests := []struct {
		pass string
		want int
	}{
		{"", 0},
		{"abc", 0},
		{"abcdefg", 0},
		{"abcdefgh", 1},
		{"abcdefghijk", 1},
		{"abcdefghijkl", 2},
		{"abcdefghijklmnop", 3},
		{"abcdefghijklmnopqrstuvwx", 4},
		{"Abcdefghijk1", 3},                   // 12 chars, 3 classes
		{"Abcdefghijklmnop1", 4},              // 17 chars, 3 classes
		{"Correct horse battery staple 1", 5}, // 30 chars, 4 classes
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1},   // long but only one distinct character
		{"abababababababababababab", 1},       // 2 distinct characters
		{"correct horse battery staple", 4},   // 28 chars, 2 classes
		{"ÄÖÜäöüßÄÖÜäöüß", 2},                 // 14 runes, other class only
	}
	for _, tc := range tests {
		got := Strength(tc.pass)
		if got != tc.want {
			t.Errorf("Strength(%q) = %d, want %d", tc.pass, got, tc.want)
		}
		if got < 0 || got > 5 {
			t.Errorf("Strength(%q) = %d out of range", tc.pass, got)
		}
	}
}
