package grid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const pw = "hunter2-very-secret"

func TestSSHLinkRequestNeverLeaksPassword(t *testing.T) {
	req := SSHLinkRequest{Address: "192.168.1.20", Port: 22, User: "pi", Password: Secret(pw)}

	outputs := map[string]string{
		"%v":   fmt.Sprintf("%v", req),
		"%+v":  fmt.Sprintf("%+v", req),
		"%#v":  fmt.Sprintf("%#v", req),
		"%s":   fmt.Sprintf("%s", req),
		"ptr":  fmt.Sprintf("%+v", &req),
		"pw%v": fmt.Sprintf("%v %s %#v", req.Password, req.Password, req.Password),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	outputs["json"] = string(b)

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("link", "req", req, "pw", req.Password)
	outputs["slog text"] = buf.String()
	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("link", "req", req, "pw", req.Password)
	outputs["slog json"] = buf.String()

	for name, out := range outputs {
		if strings.Contains(out, pw) {
			t.Errorf("%s leaks the password: %s", name, out)
		}
	}
	if got := req.Password.Reveal(); got != pw {
		t.Fatalf("Reveal = %q", got)
	}
	if !strings.Contains(outputs["%v"], "pi@192.168.1.20:22") {
		t.Errorf("String should still be informative: %s", outputs["%v"])
	}
}

func TestJobStateFinished(t *testing.T) {
	for s, want := range map[JobState]bool{JobQueued: false, JobRunning: false, JobDone: true, JobFailed: true, JobCanceled: true} {
		if s.Finished() != want {
			t.Errorf("%s.Finished() = %v", s, !want)
		}
	}
}

func TestHostInfoHasCapability(t *testing.T) {
	h := HostInfo{Capabilities: []string{"shell", "packages"}}
	if !h.HasCapability("shell") || h.HasCapability("docker") {
		t.Fatal("HasCapability wrong")
	}
}

func TestLinkSteps(t *testing.T) {
	if got := LinkSteps(); len(got) != 5 || got[0] != StepConnect || got[4] != StepOnline {
		t.Fatalf("%v", got)
	}
}
