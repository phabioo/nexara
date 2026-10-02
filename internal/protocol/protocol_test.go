package protocol

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

// roundtripCases has one sample payload for every message type.
func roundtripCases() []struct {
	typ  string
	data any
	new  func() any
} {
	ts := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	type c = struct {
		typ  string
		data any
		new  func() any
	}
	return []c{
		{TypeHello, Hello{AgentVersion: "0.1.0", ProtocolVersion: 1, Hostname: "frpi5", OS: "linux", Arch: "arm64",
			Kernel: "6.6.31", Model: "Raspberry Pi 5", Capabilities: []string{CapMonitoring, CapShell}, MAC: "d8:3a:dd:00:00:01"},
			func() any { return new(Hello) }},
		{TypeHelloAck, HelloAck{Accepted: false, Reason: "too old", UpdateRequired: true, TargetVersion: "0.1.1"},
			func() any { return new(HelloAck) }},
		{TypeMetrics, Metrics{Timestamp: ts, CPUPercent: 12.5, CPUPerCore: []float64{1, 2, 3, 4}, TempC: ptr(51.2),
			Load: [3]float64{0.1, 0.2, 0.3}, MemTotal: 8 << 30, MemUsed: 1 << 30, SwapTotal: 2 << 30, SwapUsed: 0,
			Disks:         []Disk{{Mount: "/", Total: 100, Used: 40}},
			Net:           NetRate{Iface: "eth0", RxBytesPerSec: 1000, TxBytesPerSec: 500},
			UptimeSeconds: 3600, TopProcesses: []Process{{PID: 1, Name: "systemd", User: "root", CPU: 0.5, MemBytes: 1024}}},
			func() any { return new(Metrics) }},
		{TypeServices, Services{Units: []ServiceUnit{{Name: "ssh.service", Description: "OpenBSD Secure Shell server", ActiveState: "active", SubState: "running"}},
			Ports: []ListeningPort{{Proto: "tcp", Port: 22, Process: "sshd"}}},
			func() any { return new(Services) }},
		{TypeServiceRestart, ServiceRestart{Unit: "ssh.service"}, func() any { return new(ServiceRestart) }},
		{TypePackages, Packages{Items: []Package{{Name: "curl", Summary: "tool", InstalledVersion: "1", CandidateVersion: "2", SizeBytes: 42, State: PackageUpdate}},
			RebootRequired: true}, func() any { return new(Packages) }},
		{TypePackagesSearch, PackagesSearch{Query: "htop"}, func() any { return new(PackagesSearch) }},
		{TypeJobStart, JobStart{JobID: "j1", Kind: JobPkgInstall, Package: "htop"}, func() any { return new(JobStart) }},
		{TypeJobOutput, JobOutput{JobID: "j1", Stream: StreamStderr, Line: "E: oops"}, func() any { return new(JobOutput) }},
		{TypeJobDone, JobDone{JobID: "j1", OK: false, ExitCode: 100, Error: "failed", RebootRequired: true}, func() any { return new(JobDone) }},
		{TypeJobCancel, JobCancel{JobID: "j1"}, func() any { return new(JobCancel) }},
		{TypeShellOpen, ShellOpen{SessionID: "s1", Cols: 120, Rows: 30}, func() any { return new(ShellOpen) }},
		{TypeShellData, ShellData{SessionID: "s1", Data: []byte{0x1b, '[', 'A', 0x00, 0xff}}, func() any { return new(ShellData) }},
		{TypeShellResize, ShellResize{SessionID: "s1", Cols: 80, Rows: 24}, func() any { return new(ShellResize) }},
		{TypeShellClose, ShellClose{SessionID: "s1", Reason: "exit"}, func() any { return new(ShellClose) }},
		{TypeAgentUpdate, AgentUpdate{Version: "0.1.1", SHA256: "abcd", Path: "/grid/agent/linux/arm64"}, func() any { return new(AgentUpdate) }},
		{TypeCertRenew, CertRenew{Force: true}, func() any { return new(CertRenew) }},
		{TypeCertCSR, CertCSR{CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"}, func() any { return new(CertCSR) }},
		{TypeCertIssued, CertIssued{CertPEM: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", NotAfter: ts}, func() any { return new(CertIssued) }},
		{TypeResult, Result{OK: false, Error: "nope"}, func() any { return new(Result) }},
		{TypeError, Error{Code: CodeBadRequest, Message: "bad"}, func() any { return new(Error) }},
	}
}

func TestRoundtripAllTypes(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range roundtripCases() {
		t.Run(tc.typ, func(t *testing.T) {
			seen[tc.typ] = true
			b, err := Encode(tc.typ, "req-1", tc.data)
			if err != nil {
				t.Fatal(err)
			}
			env, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if env.Type != tc.typ || env.ID != "req-1" || env.V != ProtocolVersion || !env.Compatible() {
				t.Fatalf("bad envelope: %+v", env)
			}
			out := tc.new()
			if err := json.Unmarshal(env.Data, out); err != nil {
				t.Fatal(err)
			}
			if got := reflect.ValueOf(out).Elem().Interface(); !reflect.DeepEqual(got, tc.data) {
				t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", got, tc.data)
			}
		})
	}
	// Payload-less request types.
	for _, typ := range []string{TypeServicesList, TypePackagesList} {
		b, err := Encode(typ, "x", nil)
		if err != nil {
			t.Fatal(err)
		}
		env, err := Decode(b)
		if err != nil || env.Type != typ || len(env.Data) != 0 {
			t.Fatalf("%s: %+v %v", typ, env, err)
		}
		seen[typ] = true
	}
	for typ := range knownTypes {
		if !seen[typ] {
			t.Errorf("message type %q has no roundtrip test", typ)
		}
	}
}

func TestDecodeData(t *testing.T) {
	b, _ := Encode(TypeServiceRestart, "1", ServiceRestart{Unit: "ssh.service"})
	env, _ := Decode(b)
	got, err := DecodeData[ServiceRestart](env)
	if err != nil || got.Unit != "ssh.service" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := DecodeData[ServiceRestart](Envelope{Type: TypeServiceRestart}); !errors.Is(err, ErrNoData) {
		t.Fatalf("want ErrNoData, got %v", err)
	}
	if _, err := DecodeData[ServiceRestart](Envelope{Type: TypeServiceRestart, Data: json.RawMessage(`"str"`)}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	// Unknown fields are ignored (forward compatibility).
	env = Envelope{Type: TypeResult, Data: json.RawMessage(`{"ok":true,"future":1}`)}
	if r, err := DecodeData[Result](env); err != nil || !r.OK {
		t.Fatalf("got %+v, %v", r, err)
	}
}

func TestDecodeMalformed(t *testing.T) {
	for _, in := range []string{``, `not json`, `{}`, `{"v":1}`, `[]`} {
		if _, err := Decode([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("Decode(%q) = %v, want ErrMalformed", in, err)
		}
	}
	if _, err := Encode("", "", nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("Encode with empty type: %v", err)
	}
	if _, err := Encode(TypeResult, "", make(chan int)); err == nil {
		t.Error("Encode of unmarshalable payload should fail")
	}
}

func TestVersionCompatibility(t *testing.T) {
	tests := []struct {
		v    int
		want bool
	}{{ProtocolVersion, true}, {ProtocolVersion + 1, false}, {0, false}, {-1, false}}
	for _, tt := range tests {
		if got := Compatible(tt.v); got != tt.want {
			t.Errorf("Compatible(%d) = %v", tt.v, got)
		}
	}
	// A foreign major still decodes so the hub can reject politely.
	env, err := Decode([]byte(`{"v":2,"type":"hello","data":{"agent_version":"9"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if env.Compatible() {
		t.Error("v2 envelope must be incompatible")
	}
}

func TestUnknownType(t *testing.T) {
	env, err := Decode([]byte(`{"v":1,"type":"future.thing","id":"7","data":{"a":1}}`))
	if err != nil {
		t.Fatalf("unknown types must still decode: %v", err)
	}
	if KnownType(env.Type) {
		t.Error("future.thing must not be known")
	}
	if !KnownType(TypeHello) {
		t.Error("hello must be known")
	}
}

func TestJobKind(t *testing.T) {
	tests := []struct {
		k          JobKind
		valid, pkg bool
	}{
		{JobAptUpdate, true, false}, {JobAptUpgrade, true, false}, {JobAptClean, true, false},
		{JobPkgInstall, true, true}, {JobPkgRemove, true, true}, {JobPkgUpgrade, true, true},
		{"", false, false}, {"rm_rf", false, false},
	}
	for _, tt := range tests {
		if tt.k.Valid() != tt.valid || tt.k.NeedsPackage() != tt.pkg {
			t.Errorf("%q: valid=%v needsPackage=%v", tt.k, tt.k.Valid(), tt.k.NeedsPackage())
		}
	}
}

func TestOmittedTempIsNull(t *testing.T) {
	b, _ := json.Marshal(Metrics{})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["temp_c"]; ok {
		t.Error("temp_c must be omitted when no sensor is available")
	}
}
