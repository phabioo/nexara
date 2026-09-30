// Package protocol defines the hub <-> agent wire protocol.
//
// Transport: one WebSocket per agent (agent dials the hub, mTLS), one JSON
// text frame per message. Every frame is an Envelope. The payload ("data") is
// decoded with DecodeData[T] into the struct documented for the message type.
//
// Directions are named from the sender's point of view: "agent->hub" means the
// agent sends it, "hub->agent" means the hub sends it.
//
// Request/response correlation: a request carries a non-empty Envelope.ID
// chosen by the sender. The answer repeats that ID. Unsolicited messages
// (metrics, job.output, shell.data, ...) may carry an empty ID.
//
// Versioning: ProtocolVersion is a single major number. Peers with different
// majors are incompatible (see Compatible). Adding optional JSON fields is not
// a breaking change and does not bump the version. Decode deliberately does not
// reject foreign majors so the hub can still read an incompatible "hello" and
// answer with hello.ack{accepted:false}; callers must check Envelope.Compatible.
//
// Validation of package names, unit names and similar values is NOT part of
// this package; the agent capability packages own that.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ProtocolVersion is the major protocol version spoken by this build.
const ProtocolVersion = 1

// Size limits both sides should enforce on the WebSocket (read limit).
const (
	// MaxMessageSize is the maximum size of one encoded envelope in bytes.
	MaxMessageSize = 1 << 20
	// MaxShellChunk is the recommended maximum payload of one shell.data message.
	MaxShellChunk = 32 << 10
)

// Message types (Envelope.Type).
const (
	TypeHello    = "hello"     // agent->hub, first message after connecting
	TypeHelloAck = "hello.ack" // hub->agent, answers hello (same ID)

	TypeMetrics = "metrics" // agent->hub, unsolicited, every metrics interval

	TypeServicesList   = "services.list"   // hub->agent, request; answered by TypeServices (same ID)
	TypeServices       = "services"        // agent->hub, answers services.list
	TypeServiceRestart = "service.restart" // hub->agent, request; answered by TypeResult (same ID)

	TypePackagesList = "packages.list" // hub->agent, request; answered by TypePackages (same ID)
	TypePackages     = "packages"      // agent->hub, answers packages.list and packages.search

	TypePackagesSearch = "packages.search" // hub->agent, request; answered by TypePackages (same ID), only matching items

	TypeJobStart  = "job.start"  // hub->agent, request; answered by TypeResult (accepted/rejected), then job.output and job.done
	TypeJobOutput = "job.output" // agent->hub, unsolicited, streamed while a job runs
	TypeJobDone   = "job.done"   // agent->hub, unsolicited, exactly once per accepted job
	TypeJobCancel = "job.cancel" // hub->agent, request; answered by TypeResult

	TypeShellOpen   = "shell.open"   // hub->agent, request; answered by TypeResult (same ID)
	TypeShellData   = "shell.data"   // both directions, terminal bytes
	TypeShellResize = "shell.resize" // hub->agent
	TypeShellClose  = "shell.close"  // both directions (either side ends the session)

	TypeAgentUpdate = "agent.update" // hub->agent, request; answered by TypeResult, then the agent restarts

	TypeResult = "result" // either direction, generic answer to a request without a dedicated response type
	TypeError  = "error"  // either direction, protocol level failure answering any request
)

var knownTypes = map[string]struct{}{
	TypeHello: {}, TypeHelloAck: {}, TypeMetrics: {},
	TypeServicesList: {}, TypeServices: {}, TypeServiceRestart: {},
	TypePackagesList: {}, TypePackages: {}, TypePackagesSearch: {},
	TypeJobStart: {}, TypeJobOutput: {}, TypeJobDone: {}, TypeJobCancel: {},
	TypeShellOpen: {}, TypeShellData: {}, TypeShellResize: {}, TypeShellClose: {},
	TypeAgentUpdate: {}, TypeResult: {}, TypeError: {},
}

// KnownType reports whether t is a message type of this protocol version.
// Receivers answer unknown types with an error message (CodeUnknownType) and
// keep the connection open, so newer peers can add messages.
func KnownType(t string) bool {
	_, ok := knownTypes[t]
	return ok
}

// Capability names (Hello.Capabilities, agent.yaml capabilities, hosts table).
const (
	CapMonitoring = "monitoring"
	CapPackages   = "packages"
	CapServices   = "services"
	CapShell      = "shell"
	CapPower      = "power"
	CapDocker     = "docker"
)

// Capabilities lists all capability names in display order.
func Capabilities() []string {
	return []string{CapMonitoring, CapPackages, CapServices, CapShell, CapPower, CapDocker}
}

// Error codes used in Error.Code.
const (
	CodeUnknownType        = "unknown_type"        // message type not known to the receiver
	CodeBadRequest         = "bad_request"         // payload missing or malformed
	CodeInvalidArgument    = "invalid_argument"    // payload well-formed but value rejected (e.g. bad package name)
	CodeCapabilityDisabled = "capability_disabled" // capability switched off in agent.yaml
	CodeNotFound           = "not_found"           // unknown unit, job, or session
	CodeBusy               = "busy"                // resource busy (e.g. dpkg lock timeout)
	CodeUnsupported        = "unsupported"         // not available on this platform
	CodeInternal           = "internal"            // unexpected failure on the receiver
)

// Envelope is the JSON frame carrying every message.
type Envelope struct {
	// V is the major protocol version of the sender.
	V int `json:"v"`
	// Type is one of the Type* constants.
	Type string `json:"type"`
	// ID correlates a request with its response. Optional for unsolicited messages.
	ID string `json:"id,omitempty"`
	// Data is the type specific payload; may be absent for payload-less requests.
	Data json.RawMessage `json:"data,omitempty"`
}

// Compatible reports whether a peer speaking major version v can talk to this build.
func Compatible(v int) bool { return v == ProtocolVersion }

// Compatible reports whether the envelope's version is compatible with this build.
func (e Envelope) Compatible() bool { return Compatible(e.V) }

// Errors returned by Decode and DecodeData.
var (
	// ErrMalformed means the frame is not a valid envelope (bad JSON or empty type).
	ErrMalformed = errors.New("protocol: malformed envelope")
	// ErrNoData means DecodeData was called on an envelope without payload.
	ErrNoData = errors.New("protocol: envelope has no data")
)

// Encode builds an envelope with the current ProtocolVersion and returns its
// JSON. data may be nil for payload-less messages (services.list, packages.list).
func Encode(msgType, id string, data any) ([]byte, error) {
	if msgType == "" {
		return nil, fmt.Errorf("%w: empty type", ErrMalformed)
	}
	env := Envelope{V: ProtocolVersion, Type: msgType, ID: id}
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("protocol: encode %s payload: %w", msgType, err)
		}
		env.Data = raw
	}
	return json.Marshal(env)
}

// Decode parses one frame into an Envelope. It does not check the version or
// whether the type is known; see Envelope.Compatible and KnownType.
func Decode(b []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if env.Type == "" {
		return Envelope{}, fmt.Errorf("%w: missing type", ErrMalformed)
	}
	return env, nil
}

// DecodeData unmarshals the envelope payload into T. Unknown JSON fields are
// ignored so that newer peers can add optional fields.
func DecodeData[T any](env Envelope) (T, error) {
	var v T
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return v, fmt.Errorf("%w: %s", ErrNoData, env.Type)
	}
	if err := json.Unmarshal(env.Data, &v); err != nil {
		return v, fmt.Errorf("%w: %s payload: %v", ErrMalformed, env.Type, err)
	}
	return v, nil
}
