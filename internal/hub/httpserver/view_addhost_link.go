package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
)

const (
	// linkTimeout bounds one SSH link attempt (connect, upload, enroll, wait for the agent).
	linkTimeout = 4 * time.Minute
	// maxRunningLinks is how many SSH link attempts may run at once.
	maxRunningLinks = 3
	// maxLinkEntries and linkRetention bound the in-memory attempt list.
	maxLinkEntries = 64
	linkRetention  = 30 * time.Minute
	// probeTTL is how long a shown host key can be confirmed; maxProbes bounds the list.
	probeTTL  = 10 * time.Minute
	maxProbes = 32
)

var (
	errTooManyLinks = errors.New("too many link attempts running")
	errProbeGone    = errors.New("host key check expired or already used")
)

// Phases of a code attempt, used to let the poll answer 204 while nothing changed.
const (
	codePhaseWaiting = iota
	codePhaseJoined  // a new host exists but is not online yet
	codePhaseOnline
	codePhaseExpired
)

// linkRegistry keeps the state of Add-host attempts in memory: the progress of
// SSH links (which run in the background because LinkViaSSH blocks until the
// agent is online) and the codes waiting for their agent. Nothing here is
// persisted and no credential is stored: the SSH password lives only inside
// the goroutine that calls the enroller.
type linkRegistry struct {
	mu     sync.Mutex
	links  map[string]*linkAttempt
	codes  map[string]*codeAttempt
	probes map[string]*hostKeyProbe
}

func newLinkRegistry() *linkRegistry {
	return &linkRegistry{links: map[string]*linkAttempt{}, codes: map[string]*codeAttempt{}, probes: map[string]*hostKeyProbe{}}
}

// --- host key probes (phase 1) ---------------------------------------------------------------

// hostKeyProbe is the state between the two phases of an SSH link: the host
// key the hub saw, waiting for the operator's confirmation. It is bound to the
// operator and the browser session that asked, expires after probeTTL and can
// be used once. It holds no credential.
type hostKeyProbe struct {
	id          string
	operator    string
	session     string // store.Session.IDHash
	form        views.AddHostForm
	port        int
	info        grid.HostKeyInfo
	replaceID   grid.HostID // offline host the operator chose to replace; empty otherwise
	replaceName string
	created     time.Time
}

// keyFile is the file on the host whose fingerprint the operator compares.
func keyFile(keyType string) string {
	switch {
	case strings.HasPrefix(keyType, "ecdsa-"):
		return "/etc/ssh/ssh_host_ecdsa_key.pub"
	case keyType == "ssh-rsa" || strings.HasPrefix(keyType, "rsa-"):
		return "/etc/ssh/ssh_host_rsa_key.pub"
	}
	return "/etc/ssh/ssh_host_ed25519_key.pub"
}

func (p *hostKeyProbe) view() *hostKeyConfirm {
	c := &hostKeyConfirm{
		ProbeID:     p.id,
		Target:      p.form.User + "@" + p.form.Address + ":" + strconv.Itoa(p.port),
		KeyType:     p.info.Type,
		Fingerprint: p.info.SHA256,
		KeyFile:     keyFile(p.info.Type),
	}
	if p.replaceID != "" {
		c.Replace = &replaceNotice{ID: string(p.replaceID), Name: p.replaceName}
	}
	return c
}

// addProbe stores a probe and returns it with its id. replace may be nil.
func (l *linkRegistry) addProbe(p *hostKeyProbe, replace *replaceNotice, now time.Time) *hostKeyProbe {
	p.id, p.created = newAttemptID(), now
	if replace != nil {
		p.replaceID, p.replaceName = grid.HostID(replace.ID), replace.Name
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneProbes(now)
	for len(l.probes) >= maxProbes {
		oldest, oldestAt := "", now
		for id, q := range l.probes {
			if !q.created.After(oldestAt) {
				oldest, oldestAt = id, q.created
			}
		}
		if oldest == "" {
			break
		}
		delete(l.probes, oldest)
	}
	l.probes[p.id] = p
	return p
}

func (l *linkRegistry) pruneProbes(now time.Time) {
	for id, p := range l.probes {
		if now.Sub(p.created) > probeTTL {
			delete(l.probes, id)
		}
	}
}

// getProbe returns the probe if it belongs to this operator and session and has not expired.
func (l *linkRegistry) getProbe(id, operator, session string, now time.Time) *hostKeyProbe {
	if id == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.probes[id]
	if p == nil || p.operator != operator || p.session != session || now.Sub(p.created) > probeTTL {
		return nil
	}
	return p
}

func newAttemptID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("httpserver: random source failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// --- SSH link attempts --------------------------------------------------------------------

type linkAttempt struct {
	id       string
	operator string
	form     views.AddHostForm // no secrets
	target   string            // user@address:port
	created  time.Time

	mu      sync.Mutex
	steps   []views.AddHostStep
	version int
	state   string // views.LinkState*
	errMsg  string
	host    grid.HostInfo
	hostKey string
	exists  *grid.HostExistsError // set when the link ran into an existing host
}

// existsID is the host the attempt collided with, if any.
func (a *linkAttempt) existsID() grid.HostID {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exists == nil {
		return ""
	}
	return a.exists.ID
}

var sshStepLabels = map[grid.LinkStepName]string{
	grid.StepConnect: "Connect via SSH",
	grid.StepDetect:  "Detect system",
	grid.StepInstall: "Install Grid Agent",
	grid.StepEnroll:  "Enroll & issue certificate",
	grid.StepOnline:  "Agent online",
}

func newSSHSteps(target string) []views.AddHostStep {
	steps := make([]views.AddHostStep, 0, 5)
	for _, n := range grid.LinkSteps() {
		steps = append(steps, views.AddHostStep{Label: sshStepLabels[n], State: "wait"})
	}
	steps[0].Detail = target
	return steps
}

func stepIndex(n grid.LinkStepName) int {
	for i, s := range grid.LinkSteps() {
		if s == n {
			return i
		}
	}
	return -1
}

// splitHostKey separates the host key fingerprint the enroller appends to the
// connect detail ("Connected as pi · Host key SHA256:...", decision #41).
func splitHostKey(detail string) (text, fingerprint string) {
	const marker = " · Host key "
	if i := strings.Index(detail, marker); i >= 0 {
		return strings.TrimSpace(detail[:i]), strings.TrimSpace(detail[i+len(marker):])
	}
	return detail, ""
}

// apply records one progress update of the enroller.
func (a *linkAttempt) apply(st grid.LinkStep) {
	i := stepIndex(st.Step)
	if i < 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	step := &a.steps[i]
	switch st.State {
	case grid.LinkWaiting:
		step.State = "wait"
	case grid.LinkRunning:
		step.State = "run"
	case grid.LinkDone:
		step.State = "done"
	case grid.LinkFailed:
		step.State = "fail"
	default:
		return
	}
	if st.Detail != "" {
		detail, fp := splitHostKey(st.Detail)
		step.Detail = detail
		if fp != "" {
			step.Fingerprint = fp
			a.hostKey = fp
		}
	}
	a.version++
}

func (a *linkAttempt) finish(host grid.HostInfo, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		a.state = views.LinkStateOnline
		a.host = host
		for i := range a.steps {
			a.steps[i].State = "done"
		}
	} else {
		a.state = views.LinkStateFailed
		a.errMsg = linkErrorMessage(err)
		var he *grid.HostExistsError
		if errors.As(err, &he) {
			a.exists = he
		}
	}
	a.version++
}

func (a *linkAttempt) currentVersion() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.version
}

func (a *linkAttempt) running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == views.LinkStateRunning
}

// progress builds the view of the attempt. polling adds the poll trigger while it runs.
func (a *linkAttempt) progress(polling bool) *views.AddHostProgress {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := &views.AddHostProgress{
		Target:     a.form.DisplayName,
		State:      a.state,
		Steps:      append([]views.AddHostStep(nil), a.steps...),
		Error:      a.errMsg,
		HostKeyTip: a.hostKey != "",
	}
	if p.Target == "" {
		p.Target = a.form.Address
	}
	switch a.state {
	case views.LinkStateRunning:
		p.StateLabel = "Linking…"
		if polling {
			p.PollURL = "/hosts/new/link/" + a.id + "?v=" + strconv.Itoa(a.version)
			p.PollEvery = "1s"
		}
	case views.LinkStateOnline:
		p.StateLabel = "Online"
		label := a.host.DisplayName
		if label == "" {
			label = a.host.Name
		}
		p.Target = label
		p.OpenLabel = label
		p.OpenURL = hostURL(a.host.Name)
	default:
		p.StateLabel = "Failed"
		p.Retry = true
		p.RetryURL = "/hosts/new/pane?retry=" + url.QueryEscape(a.id)
	}
	return p
}

// start validates capacity, consumes the confirmed probe, registers the
// attempt and runs the link in the background. The request's password travels
// inside req only.
func (l *linkRegistry) start(s *Server, r *http.Request, req grid.SSHLinkRequest, form views.AddHostForm, probeID string) (*linkAttempt, error) {
	now := s.now()
	l.mu.Lock()
	l.prune(now)
	running := 0
	for _, a := range l.links {
		if a.running() {
			running++
		}
	}
	if running >= maxRunningLinks {
		l.mu.Unlock()
		return nil, errTooManyLinks
	}
	if _, ok := l.probes[probeID]; !ok { // used by a concurrent request in the meantime
		l.mu.Unlock()
		return nil, errProbeGone
	}
	delete(l.probes, probeID)
	port := req.Port
	if port == 0 {
		port = 22
	}
	target := req.User + "@" + req.Address + ":" + strconv.Itoa(port)
	a := &linkAttempt{
		id: newAttemptID(), operator: operatorName(r), form: form, target: target, created: now,
		steps: newSSHSteps(target), state: views.LinkStateRunning, version: 1,
	}
	l.links[a.id] = a
	l.mu.Unlock()

	actor := ActorFrom(r)
	// The link outlives the request; it ends with the server or the timeout.
	ctx, cancel := contextWithDone(context.WithoutCancel(r.Context()), s.streamsDone)
	ctx, cancelTimeout := context.WithTimeout(ctx, linkTimeout)
	go func() {
		defer cancel()
		defer cancelTimeout()
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("host link panicked", "panic", v)
				a.finish(grid.HostInfo{}, errors.New("internal error"))
			}
		}()
		host, err := s.enroller.LinkViaSSH(ctx, actor, req, a.apply)
		if err != nil {
			s.log.Warn("host link failed", "address", req.Address, "err", err)
		}
		a.finish(host, err)
	}()
	return a, nil
}

func (l *linkRegistry) get(id, operator string) *linkAttempt {
	if id == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if a := l.links[id]; a != nil && a.operator == operator {
		return a
	}
	return nil
}

// prune drops old entries and, if the list is still too long, the oldest.
// Callers hold l.mu.
func (l *linkRegistry) prune(now time.Time) {
	for id, a := range l.links {
		if now.Sub(a.created) > linkRetention && !a.running() {
			delete(l.links, id)
		}
	}
	for id, c := range l.codes {
		if now.Sub(c.created) > linkRetention {
			delete(l.codes, id)
		}
	}
	l.pruneProbes(now)
	for len(l.links)+len(l.codes) > maxLinkEntries {
		oldestID, oldest := "", now
		isCode := false
		for id, a := range l.links {
			if !a.running() && a.created.Before(oldest) {
				oldestID, oldest, isCode = id, a.created, false
			}
		}
		for id, c := range l.codes {
			if c.created.Before(oldest) {
				oldestID, oldest, isCode = id, c.created, true
			}
		}
		if oldestID == "" {
			return
		}
		if isCode {
			delete(l.codes, oldestID)
		} else {
			delete(l.links, oldestID)
		}
	}
}

// --- enrollment codes ------------------------------------------------------------------------

// codeAttempt remembers which hosts existed when a code was created, so the
// first host that appears afterwards is the one that used it. The code itself
// is not kept.
type codeAttempt struct {
	id       string
	operator string
	known    map[grid.HostID]bool
	expires  time.Time
	created  time.Time

	mu     sync.Mutex
	hostID grid.HostID
}

func (l *linkRegistry) addCode(operator string, known map[grid.HostID]bool, expires, now time.Time) string {
	c := &codeAttempt{id: newAttemptID(), operator: operator, known: known, expires: expires, created: now}
	l.mu.Lock()
	l.prune(now)
	l.codes[c.id] = c
	l.mu.Unlock()
	return c.id
}

func (l *linkRegistry) getCode(id, operator string) *codeAttempt {
	if id == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.codes[id]; c != nil && c.operator == operator {
		return c
	}
	return nil
}

// evaluate compares the current host list with the one at code creation. It
// returns the phase and, once a host joined, the progress list for it.
func (c *codeAttempt) evaluate(hosts []grid.HostInfo, now time.Time) (int, *views.AddHostProgress) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var joined *grid.HostInfo
	for i := range hosts {
		h := hosts[i]
		if (c.hostID != "" && h.ID == c.hostID) || (c.hostID == "" && !c.known[h.ID]) {
			joined = &h
			c.hostID = h.ID
			break
		}
	}
	if joined == nil {
		if now.After(c.expires) {
			return codePhaseExpired, nil
		}
		return codePhaseWaiting, nil
	}
	label := joined.DisplayName
	if label == "" {
		label = joined.Name
	}
	p := &views.AddHostProgress{Target: label}
	details := []string{
		joined.Address,
		strings.Trim(strings.Join([]string{joined.OS, joined.Arch}, " · "), " ·"),
		"from this hub",
		"mTLS · valid 1 year",
		"first sync running",
	}
	if joined.AgentVersion != "" {
		details[2] = "v" + strings.TrimPrefix(joined.AgentVersion, "v") + " from this hub"
	}
	labels := []string{"Agent connected with code", "Detect system", "Deliver Grid Agent", "Enroll & issue certificate", "Agent online"}
	for i, l := range labels {
		p.Steps = append(p.Steps, views.AddHostStep{Label: l, Detail: details[i], State: "done"})
	}
	if joined.Online {
		p.State, p.StateLabel = views.LinkStateOnline, "Online"
		p.OpenLabel, p.OpenURL = label, hostURL(joined.Name)
		return codePhaseOnline, p
	}
	p.State, p.StateLabel = views.LinkStateRunning, "Linking…"
	p.Steps[4].State = "run"
	p.PollURL, p.PollEvery = "x", "1s" // the handler fills in the URL
	return codePhaseJoined, p
}
