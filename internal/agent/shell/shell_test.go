package shell

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestValidateSize(t *testing.T) {
	tests := []struct {
		cols, rows int
		ok         bool
	}{
		{80, 24, true},
		{1, 1, true},
		{1000, 1000, true},
		{0, 24, false},
		{80, 0, false},
		{1001, 24, false},
		{80, 1001, false},
		{-1, 24, false},
	}
	for _, tt := range tests {
		err := ValidateSize(tt.cols, tt.rows)
		if (err == nil) != tt.ok {
			t.Errorf("ValidateSize(%d,%d) = %v, want ok=%v", tt.cols, tt.rows, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidSize) {
			t.Errorf("error %v does not wrap ErrInvalidSize", err)
		}
	}
}

func TestParseLang(t *testing.T) {
	tests := []struct{ in, want string }{
		{"LANG=en_US.UTF-8\n", "en_US.UTF-8"},
		{"# c\nLANG=\"de_DE.UTF-8\"\n", "de_DE.UTF-8"},
		{"LANG='C.UTF-8'", "C.UTF-8"},
		{"LANGUAGE=en\n", ""},
		{"LANG=$(touch /x)\n", ""},
		{"LANG=a b\n", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := parseLang(strings.NewReader(tt.in)); got != tt.want {
			t.Errorf("parseLang(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPasswdShell(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nfabio:x:1000:1000:F,,,:/home/fabio:/bin/zsh\nshort:x:1\n"
	tests := []struct{ name, want string }{
		{"fabio", "/bin/zsh"},
		{"root", "/bin/bash"},
		{"short", ""},
		{"nobody", ""},
	}
	for _, tt := range tests {
		if got := passwdShell(strings.NewReader(passwd), tt.name); got != tt.want {
			t.Errorf("passwdShell(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

type fakeSession struct {
	mu     sync.Mutex
	closes int
}

func (f *fakeSession) Read([]byte) (int, error)    { return 0, nil }
func (f *fakeSession) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeSession) Resize(int, int) error       { return nil }
func (f *fakeSession) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	return nil
}

type fakeSpawner struct{ opened []*fakeSession }

func (f *fakeSpawner) Open(cols, rows int) (Session, error) {
	s := &fakeSession{}
	f.opened = append(f.opened, s)
	return s, nil
}

func TestSessionsLimitAndClose(t *testing.T) {
	sp := &fakeSpawner{}
	reg := NewSessions(sp)
	for i := range MaxSessions {
		if _, err := reg.Open(string(rune('a'+i)), 80, 24); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	if _, err := reg.Open("extra", 80, 24); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("err = %v, want ErrTooManySessions", err)
	}
	if _, err := reg.Open("a", 80, 24); !errors.Is(err, ErrSessionExists) {
		t.Fatalf("duplicate id err = %v, want ErrSessionExists", err)
	}
	if _, err := reg.Open("z", 0, 24); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("bad size err = %v, want ErrInvalidSize", err)
	}
	if err := reg.Close("a"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Close("a"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("second close err = %v, want ErrNoSession", err)
	}
	if _, err := reg.Open("extra", 80, 24); err != nil {
		t.Fatalf("open after free slot: %v", err)
	}
	reg.CloseAll()
	if reg.Len() != 0 {
		t.Fatalf("Len after CloseAll = %d", reg.Len())
	}
	for i, s := range sp.opened {
		if s.closes != 1 {
			t.Errorf("session %d closed %d times, want 1", i, s.closes)
		}
	}
}
