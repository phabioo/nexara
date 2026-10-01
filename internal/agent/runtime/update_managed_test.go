package runtime

import (
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/protocol"
)

func TestPackageManaged(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/usr/bin/grid-agent", true},
		{"/usr/sbin/grid-agent", true},
		{"/bin/grid-agent", true},
		{"/usr/bin/../local/bin/grid-agent", false},
		{"/usr/local/bin/grid-agent", false},
		{"/opt/nexara/grid-agent", false},
		{"/home/pi/usr/bin/grid-agent", false},
	} {
		if got := packageManaged(tc.path); got != tc.want {
			t.Errorf("packageManaged(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestValidateUpdateRefusesPackageManaged(t *testing.T) {
	up := protocol.AgentUpdate{Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
	a := &Agent{opts: Options{BinaryPath: "/usr/bin/grid-agent"}}
	_, err := a.validateUpdate(up)
	if err == nil || !strings.Contains(err.Error(), "managed by package; update the nexus package") {
		t.Fatalf("err = %v", err)
	}
	a = &Agent{opts: Options{BinaryPath: "/usr/local/bin/grid-agent"}}
	if _, err := a.validateUpdate(up); err != nil {
		t.Fatalf("unmanaged path refused: %v", err)
	}
}
