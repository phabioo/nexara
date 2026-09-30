package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEnrollRoundtrip(t *testing.T) {
	req := EnrollRequest{Token: "ABCD-1234", CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----\n",
		Hello: Hello{AgentVersion: "0.1.0", ProtocolVersion: 1, Hostname: "pi", OS: "linux", Arch: "arm64", Capabilities: []string{CapShell}}}
	resp := EnrollResponse{HostID: "0123456789abcdef", CertPEM: "cert", CAPEM: "ca", HubURL: "wss://frpi5.local:8443/grid/connect",
		Settings: AgentSettings{Capabilities: []string{CapMonitoring, CapPackages}}}

	var gotReq EnrollRequest
	b, _ := json.Marshal(req)
	if err := json.Unmarshal(b, &gotReq); err != nil || !reflect.DeepEqual(gotReq, req) {
		t.Fatalf("request: %+v %v", gotReq, err)
	}
	var gotResp EnrollResponse
	b, _ = json.Marshal(resp)
	if err := json.Unmarshal(b, &gotResp); err != nil || !reflect.DeepEqual(gotResp, resp) {
		t.Fatalf("response: %+v %v", gotResp, err)
	}
	var m map[string]any
	b, _ = json.Marshal(req)
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"token", "csr_pem", "hello"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
}
