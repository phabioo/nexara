package protocol

// Enrollment runs over plain HTTPS, not over the agent WebSocket: the agent has
// no certificate yet. The agent POSTs an EnrollRequest (JSON) to
// /grid/enroll on the hub and receives an EnrollResponse.
//
// Transport: server-authenticated TLS only (no client certificate). The agent
// must not trust the system roots for this call; it pins the hub CA
// fingerprint it was given at install time (installer output / enrollment
// command) and aborts if the presented chain does not match. On success the
// agent stores cert_pem, ca_pem and its private key, writes the settings
// into agent.yaml and connects to hub_url with mTLS.

// EnrollRequest is sent by the agent to the hub (agent->hub, POST /grid/enroll).
type EnrollRequest struct {
	// Token is the one-time enrollment code (plain; the hub stores only its hash).
	Token string `json:"token"`
	// CSRPEM is the PEM-encoded certificate signing request for the agent's new key.
	CSRPEM string `json:"csr_pem"`
	// Hello describes the device (same content as the later WebSocket hello).
	Hello Hello `json:"hello"`
}

// EnrollResponse is the hub's answer to a successful EnrollRequest.
type EnrollResponse struct {
	HostID  string `json:"host_id"`
	CertPEM string `json:"cert_pem"` // signed agent client certificate
	CAPEM   string `json:"ca_pem"`   // hub CA certificate
	// HubURL is the wss URL for `grid-agent run` (agent.yaml hub.url).
	HubURL   string        `json:"hub_url"`
	Settings AgentSettings `json:"settings"`
}

// AgentSettings are the operator's choices applied at enrollment.
type AgentSettings struct {
	// Capabilities lists the enabled capability names (Cap* constants), chosen
	// in the UI (setup step "Self-link", Add host) before the agent exists.
	// The agent writes them into agent.yaml. Empty means "agent defaults".
	Capabilities []string `json:"capabilities"`
}
