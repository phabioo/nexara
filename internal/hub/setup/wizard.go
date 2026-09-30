package setup

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/protocol"
)

// Step is a wizard step, in display order.
type Step int

// Wizard steps (docs/concept.md, "Setup-Assistent").
const (
	StepUnlock Step = iota
	StepTrust
	StepOperator
	StepTwoFactor
	StepHub
	StepSelfLink
	StepReady
	stepCount
)

var stepNames = [stepCount]string{"unlock", "trust", "operator", "two-factor", "hub", "self-link", "ready"}

func (s Step) String() string {
	if s < 0 || s >= stepCount {
		return "unknown"
	}
	return stepNames[s]
}

// Limits and choices from the design.
const (
	MinPassphraseLen = 12
	OperatorIDMin    = 3
	OperatorIDMax    = 32
)

// RetentionChoices are the selectable hourly-history retention values in days.
var RetentionChoices = []int{30, 90, 365}

var (
	operatorIDRe = regexp.MustCompile(`^[a-z0-9._-]+$`)
	hostLabelRe  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	// hubNameRe is the same pattern as hub.name in package config, so the name
	// the operator types is exactly the name nexus.yaml stores.
	hubNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

	// ErrStepLocked is returned when a step cannot be reached yet.
	ErrStepLocked = errors.New("setup: complete the previous steps first")
	// ErrNotReady is returned by Result before all steps are complete.
	ErrNotReady = errors.New("setup: wizard is not complete")
)

// ValidationError maps form field names to messages.
type ValidationError map[string]string

func (v ValidationError) Error() string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + v[k]
	}
	return "setup: invalid input: " + strings.Join(parts, "; ")
}

// OperatorInput is the Operator step form.
type OperatorInput struct {
	ID         string
	Passphrase string
	Confirm    string
}

// HubInput is the Hub step form. RetentionDays is the hourly-history retention.
type HubInput struct {
	Name          string
	TimeZone      string
	AgentHost     string
	HTTPSPort     int
	RetentionDays int
}

// SelfLinkInput is the Self-link step form.
type SelfLinkInput struct {
	Enabled      bool
	Capabilities []string
}

// Result is everything the wizard collected. The handler that performs the
// final commit (step "Ready") persists it; nothing is stored before that.
type Result struct {
	OperatorID string
	Passphrase string
	// TOTPSecret is the pending TOTP secret; empty when the step was skipped.
	TOTPSecret  string
	TOTPSkipped bool
	Hub         HubInput
	SelfLink    SelfLinkInput
}

// WizardOptions configures a Wizard.
type WizardOptions struct {
	// CheckPassphrase is the injected strength check (the auth package
	// provides it); it runs after the minimum-length check. May be nil.
	CheckPassphrase func(passphrase string) error
}

// Wizard is the in-memory state of one setup session.
type Wizard struct {
	opts WizardOptions

	mu   sync.Mutex
	cur  Step
	done [stepCount]bool
	res  Result
}

// NewWizard returns a wizard that starts at Trust (Unlock is already done).
func NewWizard(o WizardOptions) *Wizard {
	w := &Wizard{opts: o, cur: StepTrust}
	w.done[StepUnlock] = true
	return w
}

// furthest is the first incomplete step (capped at Ready).
func (w *Wizard) furthest() Step {
	for s := StepUnlock; s < StepReady; s++ {
		if !w.done[s] {
			return s
		}
	}
	return StepReady
}

// Current returns the step the user is on.
func (w *Wizard) Current() Step {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// Done reports whether a step is complete.
func (w *Wizard) Done(s Step) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return s >= 0 && s < stepCount && w.done[s]
}

// Goto navigates to a step. Steps beyond the first incomplete one are refused.
func (w *Wizard) Goto(s Step) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s < StepTrust || s >= stepCount {
		return fmt.Errorf("setup: unknown step %d", int(s))
	}
	if s > w.furthest() {
		return ErrStepLocked
	}
	w.cur = s
	return nil
}

// Back moves one step back (never before Trust) and returns the new step.
func (w *Wizard) Back() Step {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur > StepTrust {
		w.cur--
	}
	return w.cur
}

// complete marks step s done and advances. Caller holds w.mu and has checked
// reachability.
func (w *Wizard) complete(s Step) {
	w.done[s] = true
	w.cur = s + 1
}

func (w *Wizard) reachable(s Step) error {
	if s > w.furthest() {
		return ErrStepLocked
	}
	return nil
}

// SubmitTrust completes the Trust step. It is skippable and stores nothing.
func (w *Wizard) SubmitTrust() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reachable(StepTrust); err != nil {
		return err
	}
	w.complete(StepTrust)
	return nil
}

// SubmitOperator validates and stores the operator ID and passphrase.
func (w *Wizard) SubmitOperator(in OperatorInput) error {
	errs := ValidationError{}
	id := strings.ToLower(strings.TrimSpace(in.ID))
	switch n := utf8.RuneCountInString(id); {
	case n < OperatorIDMin || n > OperatorIDMax:
		errs["id"] = fmt.Sprintf("Use %d to %d characters.", OperatorIDMin, OperatorIDMax)
	case !operatorIDRe.MatchString(id):
		errs["id"] = "Use only letters, digits, dot, dash and underscore."
	}
	switch {
	case utf8.RuneCountInString(in.Passphrase) < MinPassphraseLen:
		errs["passphrase"] = fmt.Sprintf("Use at least %d characters.", MinPassphraseLen)
	case w.opts.CheckPassphrase != nil:
		if err := w.opts.CheckPassphrase(in.Passphrase); err != nil {
			errs["passphrase"] = err.Error()
		}
	}
	if in.Passphrase != in.Confirm {
		errs["confirm"] = "The passphrases do not match."
	}
	if len(errs) > 0 {
		return errs
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reachable(StepOperator); err != nil {
		return err
	}
	w.res.OperatorID, w.res.Passphrase = id, in.Passphrase
	w.complete(StepOperator)
	return nil
}

// SubmitTwoFactor completes the two-factor step. With skip=true (allowed in
// v0.1) no secret is stored; otherwise secret is the pending TOTP secret the
// caller already confirmed with a code.
func (w *Wizard) SubmitTwoFactor(skip bool, secret string) error {
	secret = strings.TrimSpace(secret)
	if !skip && secret == "" {
		return ValidationError{"totp": "Set up the authenticator app or skip this step."}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reachable(StepTwoFactor); err != nil {
		return err
	}
	w.res.TOTPSkipped = skip
	w.res.TOTPSecret = ""
	if !skip {
		w.res.TOTPSecret = secret
	}
	w.complete(StepTwoFactor)
	return nil
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !hostLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// SubmitHub validates and stores the hub settings.
func (w *Wizard) SubmitHub(in HubInput) error {
	errs := ValidationError{}
	in.Name = strings.TrimSpace(in.Name)
	in.TimeZone = strings.TrimSpace(in.TimeZone)
	in.AgentHost = strings.TrimSpace(in.AgentHost)
	if !hubNameRe.MatchString(in.Name) {
		errs["name"] = "Use 1 to 63 letters, digits, dots, dashes or underscores, starting with a letter or digit."
	}
	if in.TimeZone == "" || in.TimeZone == "Local" {
		errs["timezone"] = "Choose a time zone."
	} else if _, err := time.LoadLocation(in.TimeZone); err != nil {
		errs["timezone"] = "Unknown time zone."
	}
	if !validHost(in.AgentHost) {
		errs["agent_host"] = "Enter a host name or IP address."
	}
	if in.HTTPSPort < 1 || in.HTTPSPort > 65535 {
		errs["https_port"] = "Enter a port between 1 and 65535."
	}
	if !slices.Contains(RetentionChoices, in.RetentionDays) {
		errs["retention"] = "Choose one of the offered periods."
	}
	if len(errs) > 0 {
		return errs
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reachable(StepHub); err != nil {
		return err
	}
	w.res.Hub = in
	w.complete(StepHub)
	return nil
}

// SubmitSelfLink validates and stores the self-link choice. Capabilities are
// ignored (and cleared) when self-link is disabled.
func (w *Wizard) SubmitSelfLink(in SelfLinkInput) error {
	var caps []string
	if in.Enabled {
		known := protocol.Capabilities()
		bad := []string{}
		for _, c := range in.Capabilities {
			if !slices.Contains(known, c) {
				bad = append(bad, c)
			}
		}
		if len(bad) > 0 {
			return ValidationError{"capabilities": "Unknown capability: " + strings.Join(bad, ", ")}
		}
		// Keep display order, drop duplicates.
		for _, c := range known {
			if slices.Contains(in.Capabilities, c) {
				caps = append(caps, c)
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reachable(StepSelfLink); err != nil {
		return err
	}
	w.res.SelfLink = SelfLinkInput{Enabled: in.Enabled, Capabilities: caps}
	w.complete(StepSelfLink)
	return nil
}

// Draft returns what has been entered so far, for pre-filling a step the
// operator returns to. Unlike Result it works at any time, and it never
// contains the passphrase. Fields of steps not yet completed are zero.
func (w *Wizard) Draft() Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.res
	r.Passphrase = ""
	r.SelfLink.Capabilities = slices.Clone(r.SelfLink.Capabilities)
	return r
}

// Result returns the collected data once every step before Ready is complete.
func (w *Wizard) Result() (Result, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.furthest() != StepReady {
		return Result{}, ErrNotReady
	}
	r := w.res
	r.SelfLink.Capabilities = slices.Clone(r.SelfLink.Capabilities)
	return r, nil
}
