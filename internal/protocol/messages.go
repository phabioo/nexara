package protocol

import "time"

// Hello is sent by the agent right after the WebSocket is up (agent->hub,
// type "hello"). The hub answers with HelloAck using the same Envelope.ID.
type Hello struct {
	AgentVersion    string `json:"agent_version"`
	ProtocolVersion int    `json:"protocol_version"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`     // GOOS style: "linux", "windows", "darwin"
	Arch            string `json:"arch"`   // GOARCH style: "arm64", "amd64"
	Kernel          string `json:"kernel"` // e.g. "6.6.31+rpt-rpi-2712"
	Model           string `json:"model"`  // board/model, e.g. "Raspberry Pi 5 Model B Rev 1.0"; may be empty
	// Capabilities are the enabled capability names (Cap* constants).
	Capabilities []string `json:"capabilities"`
	// MAC is the primary interface MAC address (lower case, colon separated), used for Wake-on-LAN.
	MAC string `json:"mac,omitempty"`
}

// HelloAck answers Hello (hub->agent, type "hello.ack").
// If Accepted is false the hub closes the connection after sending it.
type HelloAck struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"` // human readable, set when not accepted
	// UpdateRequired is true when the agent is too old (or has an incompatible
	// protocol major) and must update to TargetVersion before it is accepted.
	UpdateRequired bool   `json:"update_required,omitempty"`
	TargetVersion  string `json:"target_version,omitempty"`
}

// Metrics is one live sample (agent->hub, type "metrics", unsolicited, ID empty).
type Metrics struct {
	Timestamp time.Time `json:"ts"` // UTC, sample time on the agent

	CPUPercent float64   `json:"cpu_percent"`            // total, 0-100
	CPUPerCore []float64 `json:"cpu_per_core,omitempty"` // one entry per logical core, 0-100
	// TempC is the SoC temperature in degrees Celsius; nil if no sensor is available.
	TempC *float64   `json:"temp_c,omitempty"`
	Load  [3]float64 `json:"load"` // 1, 5, 15 minute load average

	MemTotal  uint64 `json:"mem_total"` // bytes
	MemUsed   uint64 `json:"mem_used"`  // bytes
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`

	Disks []Disk  `json:"disks,omitempty"`
	Net   NetRate `json:"net"`

	UptimeSeconds uint64    `json:"uptime_seconds"`
	TopProcesses  []Process `json:"top_processes,omitempty"` // sorted by CPU descending
}

// Disk is one mounted filesystem.
type Disk struct {
	Mount string `json:"mount"`
	Total uint64 `json:"total"` // bytes
	Used  uint64 `json:"used"`  // bytes
}

// NetRate is the throughput of the primary interface.
type NetRate struct {
	Iface         string  `json:"iface"`
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
}

// Process is one entry of Metrics.TopProcesses.
type Process struct {
	PID      int32   `json:"pid"`
	Name     string  `json:"name"`
	User     string  `json:"user"`
	CPU      float64 `json:"cpu_percent"`
	MemBytes uint64  `json:"mem_bytes"`
}

// ServicesList has no payload (hub->agent, type "services.list"); answered by Services.
// Packages listing ("packages.list") likewise has no payload.

// Services answers services.list (agent->hub, type "services", same ID).
type Services struct {
	Units []ServiceUnit   `json:"units"`
	Ports []ListeningPort `json:"ports,omitempty"` // listening sockets summary
}

// ServiceUnit is one system service (systemd unit on Linux).
type ServiceUnit struct {
	Name        string `json:"name"` // e.g. "ssh.service"
	Description string `json:"description"`
	ActiveState string `json:"active_state"` // systemd ActiveState: active, inactive, failed, activating, ...
	SubState    string `json:"sub_state"`    // systemd SubState: running, dead, exited, failed, ...
}

// ListeningPort is one entry of the listening ports summary.
type ListeningPort struct {
	Proto   string `json:"proto"` // "tcp" or "udp"
	Port    uint16 `json:"port"`
	Process string `json:"process,omitempty"` // owning process name if known
}

// ServiceRestart asks the agent to restart a unit (hub->agent, type
// "service.restart"). Answered by Result with the same ID.
type ServiceRestart struct {
	Unit string `json:"unit"`
}

// PackageState classifies a Package row.
type PackageState string

// Package states.
const (
	PackageUpdate    PackageState = "update"    // installed, newer candidate available
	PackageInstalled PackageState = "installed" // installed and up to date
	PackageAvailable PackageState = "available" // not installed, available in the repositories
	PackageOrphaned  PackageState = "orphaned"  // installed automatically, no longer needed
)

// Package is one row of the package list.
type Package struct {
	Name             string       `json:"name"`
	Summary          string       `json:"summary"`
	InstalledVersion string       `json:"installed_version,omitempty"`
	CandidateVersion string       `json:"candidate_version,omitempty"`
	SizeBytes        int64        `json:"size_bytes"`
	State            PackageState `json:"state"`
}

// Packages answers packages.list (agent->hub, type "packages", same ID).
type Packages struct {
	Items          []Package `json:"items"`
	RebootRequired bool      `json:"reboot_required"` // /var/run/reboot-required exists
}

// PackagesSearch looks up packages by name (hub->agent, type "packages.search").
// Answered by Packages (same ID) with at most MaxSearchResults items, installed
// or available; RebootRequired is not meaningful in the answer.
type PackagesSearch struct {
	Query string `json:"query"`
}

// MaxSearchResults caps the answer to PackagesSearch.
const MaxSearchResults = 50

// JobKind is the operation of a job.
type JobKind string

// Job kinds. pkg_* kinds require JobStart.Package.
const (
	JobAptUpdate  JobKind = "apt_update"
	JobAptUpgrade JobKind = "apt_upgrade"
	JobAptClean   JobKind = "apt_clean"
	JobPkgInstall JobKind = "pkg_install"
	JobPkgRemove  JobKind = "pkg_remove"
	JobPkgUpgrade JobKind = "pkg_upgrade"
)

// Valid reports whether k is a known job kind.
func (k JobKind) Valid() bool {
	switch k {
	case JobAptUpdate, JobAptUpgrade, JobAptClean, JobPkgInstall, JobPkgRemove, JobPkgUpgrade:
		return true
	}
	return false
}

// NeedsPackage reports whether the kind operates on a single named package.
func (k JobKind) NeedsPackage() bool {
	return k == JobPkgInstall || k == JobPkgRemove || k == JobPkgUpgrade
}

// JobStart starts a job on the agent (hub->agent, type "job.start"). The agent
// answers with Result (same ID) to accept or reject it, then streams JobOutput
// and finishes with exactly one JobDone. The hub serializes jobs per host, the
// agent may assume at most one running job.
type JobStart struct {
	JobID   string  `json:"job_id"`
	Kind    JobKind `json:"kind"`
	Package string  `json:"package,omitempty"` // only for pkg_* kinds
}

// JobStream names the origin of a JobOutput line.
type JobStream string

// Job output streams.
const (
	StreamStdout JobStream = "stdout"
	StreamStderr JobStream = "stderr"
	// StreamStatus carries agent status text such as "waiting for dpkg lock (120s)".
	StreamStatus JobStream = "status"
)

// JobOutput is one output line of a running job (agent->hub, type "job.output").
type JobOutput struct {
	JobID  string    `json:"job_id"`
	Stream JobStream `json:"stream"`
	Line   string    `json:"line"` // without trailing newline
}

// JobDone reports the end of a job (agent->hub, type "job.done"). Sent exactly
// once per accepted job, also after cancellation (OK=false).
type JobDone struct {
	JobID          string `json:"job_id"`
	OK             bool   `json:"ok"`
	ExitCode       int    `json:"exit_code"`
	Error          string `json:"error,omitempty"`
	RebootRequired bool   `json:"reboot_required"`
}

// JobCancel cancels a running job (hub->agent, type "job.cancel"). Answered by
// Result; the job then ends with JobDone. Queued (not yet started) jobs are
// cancelled by the hub without contacting the agent.
type JobCancel struct {
	JobID string `json:"job_id"`
}

// ShellOpen opens a PTY session (hub->agent, type "shell.open"). Answered by
// Result with the same ID; afterwards ShellData flows in both directions.
type ShellOpen struct {
	SessionID string `json:"session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// ShellData carries terminal bytes (both directions, type "shell.data").
// Data is base64 in JSON (Go []byte). Chunks should not exceed MaxShellChunk.
type ShellData struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
}

// ShellResize changes the PTY size (hub->agent, type "shell.resize").
type ShellResize struct {
	SessionID string `json:"session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// ShellClose ends a session (both directions, type "shell.close"). The agent
// sends it when the shell process exits, the hub when the browser leaves.
type ShellClose struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}

// AgentUpdate tells the agent to replace itself (hub->agent, type
// "agent.update"). The agent answers with Result, downloads the binary over
// HTTPS from the hub using its client certificate, verifies SHA256, swaps the
// binary and restarts. It reconnects with the new version in Hello.
type AgentUpdate struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"` // lower case hex
	// Path is relative to the hub's agent URL, e.g. "/grid/agent/linux/arm64".
	Path string `json:"path"`
}

// Result is the generic answer to a request (type "result", same ID as the request).
type Result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Error reports a protocol level failure (type "error"). It may answer any
// request (same ID) instead of the expected response. Code is one of the Code*
// constants; Message is for humans and logs.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface so a received Error can be returned directly.
func (e Error) Error() string { return "protocol: " + e.Code + ": " + e.Message }
