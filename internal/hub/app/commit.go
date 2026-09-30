package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/httpserver"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Audit action of the setup commit.
const ActionSetupCommit = "setup.commit"

// SelfEnrollTokenFile is the name of the self-link token inside the data
// directory (next to the database). The hub's own agent reads it through
// `enroll.token_file` in agent.yaml (decision #38).
const SelfEnrollTokenFile = "self-enroll.token"

// committer implements httpserver.SetupCommitFunc.
type committer struct {
	st       *store.Store
	auth     *auth.Service
	codes    *setup.Codes
	sessions *setup.Sessions
	mode     *setup.Mode
	log      *slog.Logger

	// configPath is nexus.yaml; empty means "do not write it" (dev mode).
	configPath string
	// listenPort is the port the hub listens on; an agent address with another
	// port is written as host:port.
	listenPort int
	// applyHub puts the new hub settings into effect in the running process
	// (certificate SANs, enrollment URLs). Nil skips it.
	applyHub func(cfg config.HubConfig) error
	// selfLink writes the self-link token for the hub's own agent with the
	// chosen capabilities. Nil means the mode has no self-link (demo).
	selfLink func(ctx context.Context, caps []string) error

	mu sync.Mutex // commits are serialized: at most one operator can be created
}

// Commit implements httpserver.SetupCommitFunc; see its contract.
//
// Order: everything that can fail without side effects comes first (hashing,
// sealing, building and saving nexus.yaml); creating the operator is the
// point of no return. After it, problems are reported as warnings and the
// setup mode is closed in any case, so the hub never stays half open.
func (c *committer) Commit(ctx context.Context, res setup.Result, clientIP string) (httpserver.SetupOutcome, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n, err := c.st.CountUsers(ctx)
	if err != nil {
		return httpserver.SetupOutcome{}, fmt.Errorf("app: count users: %w", err)
	}
	if n > 0 {
		return httpserver.SetupOutcome{}, httpserver.ErrSetupDone
	}

	hash, err := c.auth.HashPassphrase(ctx, res.Passphrase)
	if err != nil {
		if errors.Is(err, auth.ErrWeakPassphrase) {
			return httpserver.SetupOutcome{}, setup.ValidationError{"passphrase": auth.UserMessage(err)}
		}
		return httpserver.SetupOutcome{}, fmt.Errorf("app: hash passphrase: %w", err)
	}
	var sealed []byte
	if res.TOTPSecret != "" {
		if sealed, err = c.auth.SealTOTPSecret(res.TOTPSecret); err != nil {
			return httpserver.SetupOutcome{}, fmt.Errorf("app: seal TOTP secret: %w", err)
		}
	}

	var newCfg config.HubConfig
	written := false
	if c.configPath != "" {
		cur, err := config.LoadHub(c.configPath)
		if err != nil {
			return httpserver.SetupOutcome{}, fmt.Errorf("app: %w", err)
		}
		newCfg = hubConfigFrom(cur, res.Hub, c.listenPort)
		if err := newCfg.Validate(); err != nil {
			var verr *config.ValidationError
			if errors.As(err, &verr) {
				return httpserver.SetupOutcome{}, setup.ValidationError{"hub": strings.Join(verr.Problems, "; ")}
			}
			return httpserver.SetupOutcome{}, err
		}
		if err := config.SaveHub(c.configPath, newCfg); err != nil {
			return httpserver.SetupOutcome{}, fmt.Errorf("app: write %s: %w", c.configPath, err)
		}
		written = true
	}

	user, err := c.st.CreateUser(ctx, store.User{
		OperatorID: res.OperatorID, PassHash: hash,
		TOTPSecretEnc: sealed, TOTPEnabled: sealed != nil,
	})
	if errors.Is(err, store.ErrExists) {
		return httpserver.SetupOutcome{}, httpserver.ErrSetupDone
	}
	if err != nil {
		return httpserver.SetupOutcome{}, fmt.Errorf("app: create operator: %w", err)
	}

	// --- point of no return: the operator exists ---
	out := httpserver.SetupOutcome{OperatorID: user.OperatorID}
	warn := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		c.log.Warn("setup commit", "warning", msg)
		out.Warnings = append(out.Warnings, msg)
	}

	if written && c.applyHub != nil {
		if err := c.applyHub(newCfg); err != nil {
			warn("The new hub settings could not be applied; restart the hub to apply them.")
			c.log.Error("setup commit: apply hub settings", "err", err)
		}
	}

	// Close the setup mode before the agent can ask for the gate to open.
	c.mode.Invalidate()
	c.codes.Invalidate()
	c.sessions.Clear()

	selfLink := "off"
	if res.SelfLink.Enabled && c.selfLink != nil {
		caps := res.SelfLink.Capabilities
		if caps == nil {
			caps = []string{} // nothing selected means no capabilities, not "defaults"
		}
		if err := c.selfLink(ctx, caps); err != nil {
			selfLink = "failed"
			warn("The hub's own agent could not be linked automatically; add it with an enrollment code.")
			c.log.Error("setup commit: self-link", "err", err)
		} else {
			selfLink = "token written"
			out.SelfLink = true
		}
	}

	twoFactor := "skipped"
	if sealed != nil {
		twoFactor = "on"
	}
	cfgState := "unchanged"
	if written {
		cfgState = "written"
	}
	detail := fmt.Sprintf("2fa: %s; self-link: %s; nexus.yaml: %s; ip: %s", twoFactor, selfLink, cfgState, clientIP)
	result := store.AuditOK
	if len(out.Warnings) > 0 {
		result = store.AuditError
	}
	if _, err := c.st.AppendAudit(ctx, store.AuditEntry{
		User: user.OperatorID, Action: ActionSetupCommit, Detail: detail, Result: result,
	}); err != nil {
		c.log.Error("setup commit: audit write failed", "err", err)
	}
	c.log.Info("setup complete", "operator", user.OperatorID, "two_factor", twoFactor, "self_link", selfLink)
	return out, nil
}

var hubNameInvalid = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// hubConfigName turns the free-text hub name of the wizard into a value
// config.HubConfig accepts (letters, digits, '.', '_', '-'; 1-63 characters).
func hubConfigName(name string) string {
	n := strings.Trim(hubNameInvalid.ReplaceAllString(strings.TrimSpace(name), "-"), "-._")
	if len(n) > 63 {
		n = strings.Trim(n[:63], "-._")
	}
	if n == "" {
		return "nexus"
	}
	return n
}

// agentAddressFor builds hub.agent_address: the host, plus the port only when
// it differs from the port the hub listens on.
func agentAddressFor(host string, port, listenPort int) string {
	host = strings.TrimSpace(host)
	if port == listenPort && !strings.Contains(host, ":") {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// hubConfigFrom applies the Hub step of the wizard to the current nexus.yaml.
func hubConfigFrom(cur config.HubConfig, in setup.HubInput, listenPort int) config.HubConfig {
	cur.Hub.Name = hubConfigName(in.Name)
	cur.Hub.Timezone = in.TimeZone
	cur.Hub.AgentAddress = agentAddressFor(in.AgentHost, in.HTTPSPort, listenPort)
	cur.Storage.History.HourDays = in.RetentionDays
	return cur
}

// resolveAgentAddress splits hub.agent_address into host and port. An empty
// address falls back to defaultHost; a missing port to listenPort.
func resolveAgentAddress(addr, defaultHost string, listenPort int) (host string, port int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return defaultHost, listenPort
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			return h, n
		}
	}
	return strings.Trim(addr, "[]"), listenPort
}
