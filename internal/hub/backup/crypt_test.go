package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func seal(t testing.TB, k Key, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := Encrypt(&buf, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(data []byte, k Key) ([]byte, error) {
	r, err := Decrypt(bytes.NewReader(data), k)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

var (
	passKey  = PassphraseKey(testPass, testKDF)
	localKey = LocalKey(bytes.Repeat([]byte{7}, 32))
)

func TestEnvelopeRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize, 3*chunkSize + 5}
	for _, kc := range []struct {
		name string
		key  Key
	}{{"passphrase", passKey}, {"local", localKey}} {
		for _, n := range sizes {
			t.Run(kc.name, func(t *testing.T) {
				plain := randBytes(t, n)
				got, err := open(seal(t, kc.key, plain), kc.key)
				if err != nil {
					t.Fatalf("size %d: %v", n, err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("size %d: plaintext differs", n)
				}
			})
		}
	}
}

func TestEnvelopeIsRandomized(t *testing.T) {
	plain := randBytes(t, 1000)
	a, b := seal(t, passKey, plain), seal(t, passKey, plain)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same data are identical (salt/nonce prefix not random)")
	}
	if bytes.Contains(a, plain[:64]) {
		t.Fatal("plaintext visible in the output")
	}
}

func TestEnvelopeWrongKey(t *testing.T) {
	data := seal(t, passKey, randBytes(t, 2*chunkSize+10))
	tests := []struct {
		name string
		key  Key
		want error
	}{
		{"wrong passphrase", PassphraseKey("another passphrase!", testKDF), ErrAuth},
		{"empty passphrase", PassphraseKey("", testKDF), nil},
		{"local key on passphrase file", localKey, ErrWrongKeyKind},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := open(data, tc.key)
			if err == nil {
				t.Fatal("opened with the wrong key")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	loc := seal(t, localKey, []byte("x"))
	if _, err := open(loc, passKey); !errors.Is(err, ErrWrongKeyKind) {
		t.Errorf("passphrase on local file: %v", err)
	}
	if _, err := open(loc, LocalKey(bytes.Repeat([]byte{8}, 32))); !errors.Is(err, ErrAuth) {
		t.Errorf("other secret.key: %v", err)
	}
}

func TestEnvelopeTamperingIsDetected(t *testing.T) {
	const chunks = 4
	plain := randBytes(t, chunks*chunkSize-100) // 4 chunks, the last one short
	orig := seal(t, passKey, plain)
	ctLen := chunkSize + tagSize
	chunk := func(i int) (int, int) { // byte range of chunk i in the file
		start := headerSize + i*ctLen
		return start, min(start+ctLen, len(orig))
	}
	if got := (len(orig) - headerSize + ctLen - 1) / ctLen; got != chunks {
		t.Fatalf("test assumes %d chunks, got %d", chunks, got)
	}

	mut := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(orig)) }
	tests := []struct {
		name string
		data []byte
	}{
		{"bit flip in header salt", mut(func(b []byte) []byte { b[20] ^= 1; return b })},
		{"bit flip in header nonce prefix", mut(func(b []byte) []byte { b[headerSize-1] ^= 1; return b })},
		{"bit flip in chunk 0", mut(func(b []byte) []byte { b[headerSize+10] ^= 1; return b })},
		{"bit flip in middle chunk", mut(func(b []byte) []byte { s, _ := chunk(1); b[s+500] ^= 0x80; return b })},
		{"bit flip in last chunk", mut(func(b []byte) []byte { b[len(b)-20] ^= 1; return b })},
		{"bit flip in last tag", mut(func(b []byte) []byte { b[len(b)-1] ^= 1; return b })},
		{"truncated mid chunk", orig[:len(orig)-50]},
		{"truncated to last chunk boundary", orig[:func() int { s, _ := chunk(chunks - 1); return s }()]},
		{"truncated to one chunk", orig[:func() int { _, e := chunk(0); return e }()]},
		{"truncated to header", orig[:headerSize]},
		{"truncated to nothing", nil},
		{"one byte appended", append(bytes.Clone(orig), 0)},
		{"garbage chunk appended", append(bytes.Clone(orig), randBytes(t, ctLen)...)},
		{"valid-looking chunk appended", mut(func(b []byte) []byte { s, e := chunk(0); return append(b, b[s:e]...) })},
		{"chunks 1 and 2 swapped", mut(func(b []byte) []byte {
			s1, e1 := chunk(1)
			s2, e2 := chunk(2)
			c1, c2 := bytes.Clone(b[s1:e1]), bytes.Clone(b[s2:e2])
			copy(b[s1:], c2)
			copy(b[s2:], c1)
			return b
		})},
		{"chunk repeated", mut(func(b []byte) []byte { s1, e1 := chunk(1); s2, _ := chunk(2); copy(b[s2:], b[s1:e1]); return b })},
		{"chunk 1 removed", mut(func(b []byte) []byte {
			s, e := chunk(1)
			return append(b[:s], b[e:]...)
		})},
		{"chunk 0 removed", mut(func(b []byte) []byte {
			s, e := chunk(0)
			return append(b[:s], b[e:]...)
		})},
	}
	if _, err := open(orig, passKey); err != nil {
		t.Fatalf("untouched file does not open: %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := open(tc.data, passKey)
			if err == nil {
				t.Fatalf("tampered file opened (%d bytes read)", len(got))
			}
		})
	}
}

func TestEnvelopeHeaderChecks(t *testing.T) {
	good := seal(t, passKey, []byte("hello"))
	patch := func(i int, v byte) []byte { b := bytes.Clone(good); b[i] = v; return b }
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrNotBackup},
		{"text file", []byte("this is just a text file, not a backup at all, really"), ErrNotBackup},
		{"newer envelope version", patch(len(envelopeMagic), 2), ErrUnsupportedFormat},
		{"unknown key kind", patch(len(envelopeMagic)+1, 9), ErrNotBackup},
		{"other chunk size", patch(len(envelopeMagic)+2, 12), ErrNotBackup},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := open(tc.data, passKey); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestEnvelopeKDFBounds(t *testing.T) {
	// A hostile header must not make us allocate gigabytes.
	b := seal(t, passKey, []byte("x"))
	off := len(envelopeMagic) + 3 + 4 // memory field
	b[off], b[off+1], b[off+2], b[off+3] = 0xff, 0xff, 0xff, 0xff
	if _, err := open(b, passKey); err == nil {
		t.Fatal("accepted an absurd argon2 memory cost")
	}
	if _, err := Encrypt(io.Discard, PassphraseKey("", testKDF)); err == nil {
		t.Error("empty passphrase accepted")
	}
	if _, err := Encrypt(io.Discard, Key{}); err == nil {
		t.Error("zero key accepted")
	}
}

func TestKindOf(t *testing.T) {
	for _, tc := range []struct {
		key  Key
		want string
	}{{passKey, "passphrase"}, {localKey, "local"}} {
		got, err := KindOf(bytes.NewReader(seal(t, tc.key, []byte("x"))))
		if err != nil || got != tc.want {
			t.Errorf("KindOf = %q, %v; want %q", got, err, tc.want)
		}
	}
	if _, err := KindOf(bytes.NewReader([]byte("nope"))); !errors.Is(err, ErrNotBackup) {
		t.Errorf("KindOf(garbage) = %v", err)
	}
}

func TestEnvelopeWriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	w, err := Encrypt(&buf, localKey)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("a"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("b")); err == nil {
		t.Error("write after close succeeded")
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
}
