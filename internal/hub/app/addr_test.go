package app

import "testing"

func TestLoopbackAddr(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"127.0.0.1:8080", "127.0.0.1:8080", false},
		{"127.0.0.1:0", "127.0.0.1:0", false},
		{"127.1.2.3:80", "127.1.2.3:80", false},
		{"[::1]:8080", "[::1]:8080", false},
		{"localhost:8080", "127.0.0.1:8080", false},
		// Anything that could be reached from the network is refused.
		{":8080", "", true},
		{"0.0.0.0:8080", "", true},
		{"[::]:8080", "", true},
		{"192.168.1.10:8080", "", true},
		{"10.0.0.5:8080", "", true},
		{"frpi5.local:8080", "", true},
		{"example.com:80", "", true},
		{"localhost.example.com:80", "", true},
		// Malformed.
		{"127.0.0.1", "", true},
		{"", "", true},
		{"127.0.0.1:http", "", true},
		{"127.0.0.1:70000", "", true},
		{"127.0.0.1:-1", "", true},
	}
	for _, tt := range tests {
		got, err := LoopbackAddr(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("LoopbackAddr(%q) = %q, %v; want %q (error %v)", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}
