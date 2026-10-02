package update

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func runShExit(code int) error {
	err := exec.Command("sh", "-c", "exit "+string(rune('0'+code))).Run()
	return err
}

func TestExecRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	var out bytes.Buffer
	err := ExecRunner{}.Run(context.Background(),
		Command{Name: "sh", Args: []string{"-c", `echo out; echo err >&2; echo "$DEBIAN_FRONTEND $EXTRA $HOME"; exit 3`}, Env: []string{"EXTRA=x"}}, &out)
	if exitCode(err) != 3 {
		t.Fatalf("exit code = %d (err %v), want 3", exitCode(err), err)
	}
	got := out.String()
	if !strings.Contains(got, "out\n") || !strings.Contains(got, "err\n") || !strings.Contains(got, "noninteractive x \n") {
		t.Fatalf("output = %q (environment must be fixed, HOME unset)", got)
	}
	if err := (ExecRunner{}).Run(context.Background(), Command{Name: "definitely-not-a-tool"}, &out); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if exitCode(errors.New("x")) != -1 {
		t.Fatal("exitCode of a non-exit error")
	}
}

func TestTailBuffer(t *testing.T) {
	tb := &tailBuffer{max: 20}
	for i := 0; i < 10; i++ {
		tb.Write([]byte("0123456789\n"))
	}
	got := tb.String()
	if len(got) > 20 || !strings.HasSuffix(got, "\n") || strings.Contains(got, "\n\n") {
		t.Fatalf("tail = %q", got)
	}
	short := &tailBuffer{max: 100}
	short.Write([]byte("hi\n"))
	if short.String() != "hi\n" {
		t.Fatalf("short = %q", short.String())
	}
}

func TestTailBufferDropsDpkgProgress(t *testing.T) {
	tb := &tailBuffer{max: 4096}
	tb.Write([]byte("Unpacking nexus (0.3.0) over (0.2.0) ...\n(Reading database ... \r(Reading database ... 5%\r(Reading database ... 100%\r(Reading database ... 55407 files and directories currently installed.)\nSetting up nexus (0.3.0) ...\n"))
	want := "Unpacking nexus (0.3.0) over (0.2.0) ...\n(Reading database ... 55407 files and directories currently installed.)\nSetting up nexus (0.3.0) ...\n"
	if got := tb.String(); got != want {
		t.Fatalf("tail = %q", got)
	}
}
