package agentbin

import "testing"

func TestLookupMissing(t *testing.T) {
	if _, ok := Lookup("plan9", "mips"); ok {
		t.Fatal("unexpected binary for plan9/mips")
	}
	for _, p := range Available() {
		if p == "" {
			t.Fatal("empty entry")
		}
	}
}
