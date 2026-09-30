package services

import (
	"reflect"
	"testing"

	"github.com/phabioo/nexara/internal/protocol"
)

const tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0F01A8C0:0016 0A01A8C0:D2F2 01 00000000:00000000 02:000A3B2E 00000000     0        0 1003 2 0000000000000000 20 4 30 10 -1
`

const tcp6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
`

const udpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
  11: 0F01A8C0:1234 0A01A8C0:0035 01 00000000:00000000 00:00000000 00000000     0        0 3002 2 0000000000000000 0
`

func TestParseProcNet(t *testing.T) {
	tests := []struct {
		name, proto, in string
		want            []listener
	}{
		{"tcp listen only", "tcp", tcpFixture, []listener{{"tcp", 22, 1001}, {"tcp", 8080, 1002}}},
		{"tcp6", "tcp", tcp6Fixture, []listener{{"tcp", 22, 2001}, {"tcp", 80, 2002}}},
		{"udp unconnected only", "udp", udpFixture, []listener{{"udp", 68, 3001}}},
		{"empty", "tcp", "", nil},
		{"garbage", "tcp", "hdr\nnot a line\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseProcNet(tt.proto, tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSocketLink(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"socket:[12345]", 12345, true},
		{"pipe:[12345]", 0, false},
		{"socket:[abc]", 0, false},
		{"socket:[12", 0, false},
		{"/dev/null", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseSocketLink(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("%q: got %d,%v want %d,%v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSummarizePorts(t *testing.T) {
	ls := []listener{
		{"tcp", 22, 1001}, {"tcp", 22, 2001}, // v4 + v6
		{"tcp", 80, 2002}, {"udp", 68, 3001}, {"tcp", 8080, 1002}, {"udp", 22, 9},
	}
	owners := map[uint64]string{2001: "sshd", 1002: "nginx", 3001: "dhcpcd"}
	got := summarizePorts(ls, owners)
	want := []protocol.ListeningPort{
		{Proto: "tcp", Port: 22, Process: "sshd"}, // owner taken from the second socket
		{Proto: "tcp", Port: 80},
		{Proto: "tcp", Port: 8080, Process: "nginx"},
		{Proto: "udp", Port: 22},
		{Proto: "udp", Port: 68, Process: "dhcpcd"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}
