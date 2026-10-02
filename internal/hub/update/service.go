package update

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Audit actions written by the hub.
const (
	ActionCheck    = "update.check"
	ActionStage    = "update.stage"
	ActionRequest  = "update.request"
	ActionApply    = "update.apply"
	ActionSettings = "update.settings"

	systemActor = "system"
)

const (
	checkEvery       = 6 * time.Hour
	checkRetryEvery  = time.Hour
	manualCheckEvery = 30 * time.Second
	defaultPollEvery = 15 * time.Second
	// staleAfter is how long a request or a running update may last before
	// the hub treats the helper as gone (the helper's own limit is shorter).
	staleAfter = 30 * time.Minute
)

// Options configure a Service. Dir is required.
type Options struct {
	// Dir is the updates directory (<data dir>/updates), owned by the hub user.
	Dir      string
	Settings Settings // nil: defaults (check off, stable channel)
	// Audit receives audit entries; nil drops them.
	Audit  func(context.Context, store.AuditEntry)
	Logger *slog.Logger
	Now    func() time.Time

	// CurrentVersion defaults to buildinfo.Version, Arch to the host's.
	CurrentVersion string
	Arch           string
	// HelperWatches tells whether nexus-update.path watches Dir. Only the
	// packaged data directory is; elsewhere (dev, manual installs) updating
	// from the UI is not available but staging still works.
	HelperWatches bool
	// PollEvery is how often Run reads the result file and checks whether a
	// GitHub check is due.
	PollEvery time.Duration

	// Key defaults to the embedded release key; tests inject their own.
	Key ed25519.PublicKey

	// GitHub access (tests point these at an httptest server).
	HTTPClient   *http.Client
	APIBase      string
	DownloadBase string
	AllowedHosts []string // additional hosts, tests only
}

// Service is the hub side of the self-update. Its methods are what the
// Settings view calls; see the package documentation.
type Service struct {
	o   Options
	log *slog.Logger
	now func() time.Time
	gh  *githubClient

	opMu sync.Mutex // one stage or request at a time

	mu          sync.Mutex // guards the fields below
	check       *CheckResult
	lastManual  time.Time
	checkingNow bool
}

// New creates the service and creates the updates directory (0700).
func New(o Options) (*Service, error) {
	if o.Dir == "" {
		return nil, errors.New("update: Options.Dir is required")
	}
	if o.CurrentVersion == "" {
		o.CurrentVersion = buildinfo.Version
	}
	if o.Arch == "" {
		arch, err := HostArch()
		if err != nil {
			return nil, err
		}
		o.Arch = arch
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PollEvery <= 0 {
		o.PollEvery = defaultPollEvery
	}
	if o.HTTPClient == nil {
		o.HTTPClient = defaultHTTPClient()
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("update: create %s: %w", o.Dir, err)
	}
	s := &Service{o: o, log: log, now: o.Now, gh: newGitHubClient(o, o.HTTPClient)}
	var cached CheckResult
	if err := readJSON(filepath.Join(o.Dir, checkCacheFile), MaxResultBytes, &cached); err == nil && !cached.CheckedAt.IsZero() {
		s.check = &cached
	}
	return s, nil
}

// Run reads helper results and runs the periodic GitHub check until ctx ends.
func (s *Service) Run(ctx context.Context) {
	s.cleanup()
	s.tick(ctx)
	t := time.NewTicker(s.o.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

// tick is one iteration of Run.
func (s *Service) tick(ctx context.Context) {
	if _, err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("update: reading the helper result failed", "err", err)
	}
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil || !cfg.CheckGitHub {
		return
	}
	s.mu.Lock()
	due := s.checkDueLocked()
	s.mu.Unlock()
	if !due {
		return
	}
	if _, err := s.doCheck(ctx, cfg); err != nil && ctx.Err() == nil {
		s.log.Warn("update: GitHub check failed", "err", err)
	}
}

func (s *Service) checkDueLocked() bool {
	if s.check == nil {
		return true
	}
	every := checkEvery
	if s.check.Error != "" {
		every = checkRetryEvery
	}
	return s.now().Sub(s.check.CheckedAt) >= every
}

// Config returns the update settings.
func (s *Service) Config(ctx context.Context) (Config, error) { return loadConfig(ctx, s.o.Settings) }

// SetConfig stores the update settings and audits the change.
func (s *Service) SetConfig(ctx context.Context, actor string, c Config) error {
	err := saveConfig(ctx, s.o.Settings, c)
	s.audit(ctx, actor, ActionSettings,
		fmt.Sprintf("check_github=%t channel=%s allow_downgrade=%t", c.CheckGitHub, c.Channel, c.AllowDowngrade), err)
	return err
}

func (s *Service) audit(ctx context.Context, actor, action, detail string, err error) {
	if s.o.Audit == nil {
		return
	}
	if actor == "" {
		actor = systemActor
	}
	res := store.AuditOK
	if err != nil {
		res = store.AuditError
		detail += ": " + err.Error()
	}
	s.o.Audit(ctx, store.AuditEntry{User: actor, Action: action, Detail: detail, Result: res})
}

// --- GitHub check ---

// CheckResult is the cached outcome of the GitHub check.
type CheckResult struct {
	CheckedAt time.Time `json:"checked_at"`
	Current   string    `json:"current"`
	Channel   string    `json:"channel"`
	// Latest is the newest release for this machine, nil if there is none.
	Latest          *Release `json:"latest,omitempty"`
	UpdateAvailable bool     `json:"update_available"`
	// Error is the failure of the latest attempt; Latest then still holds the
	// last good answer.
	Error string `json:"error,omitempty"`
}

// CheckNow asks GitHub for the newest release (the "Check now" button). It
// fails with ErrCheckDisabled while the setting is off. Calls within 30
// seconds of the previous manual check return the cached result.
func (s *Service) CheckNow(ctx context.Context, actor string) (CheckResult, error) {
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil {
		return CheckResult{}, err
	}
	if !cfg.CheckGitHub {
		return CheckResult{}, ErrCheckDisabled
	}
	s.mu.Lock()
	if s.check != nil && s.now().Sub(s.lastManual) < manualCheckEvery {
		c := *s.check
		s.mu.Unlock()
		return c, nil
	}
	s.lastManual = s.now()
	s.mu.Unlock()
	res, err := s.doCheck(ctx, cfg)
	detail := "channel " + cfg.Channel
	if err == nil && res.Latest != nil {
		detail += ", latest " + res.Latest.Version
	}
	s.audit(ctx, actor, ActionCheck, detail, err)
	return res, err
}

func (s *Service) doCheck(ctx context.Context, cfg Config) (CheckResult, error) {
	s.mu.Lock()
	if s.checkingNow {
		var c CheckResult
		if s.check != nil {
			c = *s.check
		}
		s.mu.Unlock()
		return c, nil
	}
	s.checkingNow = true
	prev := s.check
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.checkingNow = false
		s.mu.Unlock()
	}()

	rel, found, err := s.gh.latest(ctx, cfg.Channel, s.o.Arch)
	res := CheckResult{CheckedAt: s.now(), Current: s.o.CurrentVersion, Channel: cfg.Channel}
	if err != nil {
		res.Error = err.Error()
		if prev != nil && prev.Channel == cfg.Channel {
			res.Latest, res.UpdateAvailable = prev.Latest, prev.UpdateAvailable
		}
	} else if found {
		res.Latest = &rel
		res.UpdateAvailable = s.newer(rel.Version)
	}
	s.mu.Lock()
	s.check = &res
	s.mu.Unlock()
	if werr := writeJSONAtomic(s.o.Dir, checkCacheFile, res, 0o600); werr != nil {
		s.log.Warn("update: caching the check result failed", "err", werr)
	}
	return res, err
}

// newer reports whether version is newer than the running one.
func (s *Service) newer(version string) bool {
	cur, err := ParseVersion(s.o.CurrentVersion)
	if err != nil {
		return false
	}
	v, err := ParseVersion(version)
	return err == nil && v.Compare(cur) > 0
}

// --- status ---

// Staged is a verified bundle waiting in the updates directory.
type Staged struct {
	Version  string    `json:"version"`
	Arch     string    `json:"arch"`
	Deb      string    `json:"deb"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	StagedAt time.Time `json:"staged_at"`
	Source   string    `json:"source"` // "github" or "upload"
}

// Installing describes an update the helper has been asked to run.
type Installing struct {
	Version     string    `json:"version"`
	Phase       string    `json:"phase"` // Phase* constants
	RequestedBy string    `json:"requested_by,omitempty"`
	Since       time.Time `json:"since"`
	// Stale is true when nothing has happened for 30 minutes: the helper
	// never picked the request up or died. A new request is then allowed.
	Stale bool `json:"stale"`
}

// Status is everything the Updates card shows.
type Status struct {
	Current string `json:"current"`
	Arch    string `json:"arch"`
	// Supported is false when the helper does not watch this hub's data
	// directory; the view then offers staging only.
	Supported bool   `json:"supported"`
	Config    Config `json:"config"`
	// Check is the cached GitHub check; nil while the check is off or has
	// never run.
	Check      *CheckResult `json:"check,omitempty"`
	Staged     []Staged     `json:"staged,omitempty"`
	Installing *Installing  `json:"installing,omitempty"`
	// Last is the outcome of the most recent update the helper reported.
	Last *Result `json:"last,omitempty"`
}

// Status reads the current state from memory and from the updates directory.
func (s *Service) Status(ctx context.Context) (Status, error) {
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil {
		return Status{}, err
	}
	st := Status{Current: s.o.CurrentVersion, Arch: s.o.Arch, Supported: s.o.HelperWatches, Config: cfg}
	s.mu.Lock()
	if s.check != nil && cfg.CheckGitHub {
		c := *s.check
		// The cache may predate an update; judge it against the running version.
		c.Current = s.o.CurrentVersion
		c.UpdateAvailable = c.Latest != nil && s.newer(c.Latest.Version)
		st.Check = &c
	}
	s.mu.Unlock()
	st.Staged = s.listStaged()
	st.Installing = s.installing()
	var last Result
	if err := readJSON(filepath.Join(s.o.Dir, LastResultFile), MaxResultBytes, &last); err == nil {
		st.Last = &last
	}
	return st, nil
}

func (s *Service) installing() *Installing {
	var ap Applying
	if err := readJSON(filepath.Join(s.o.Dir, ApplyingFile), MaxRequestBytes, &ap); err == nil {
		return &Installing{Version: ap.Version, Phase: orStr(ap.Phase, PhaseVerify), RequestedBy: ap.RequestedBy,
			Since: ap.StartedAt, Stale: s.now().Sub(ap.StartedAt) > staleAfter}
	}
	var rq Request
	if err := readJSON(filepath.Join(s.o.Dir, RequestFile), MaxRequestBytes, &rq); err == nil {
		return &Installing{Version: rq.Version, Phase: PhaseQueued, RequestedBy: rq.RequestedBy,
			Since: rq.RequestedAt, Stale: s.now().Sub(rq.RequestedAt) > staleAfter}
	}
	return nil
}

func (s *Service) listStaged() []Staged {
	entries, err := os.ReadDir(s.o.Dir)
	if err != nil {
		return nil
	}
	var out []Staged
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		v, err := ParseVersion(e.Name())
		if err != nil || v.String() != e.Name() {
			continue
		}
		deb := DebName(v.String(), s.o.Arch)
		fi, err := os.Lstat(filepath.Join(s.o.Dir, e.Name(), deb))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		sums, err := readLimited(filepath.Join(s.o.Dir, e.Name(), SumsFile), MaxSumsBytes)
		if err != nil {
			continue
		}
		st := Staged{Version: v.String(), Arch: s.o.Arch, Deb: deb, Size: fi.Size(), StagedAt: fi.ModTime()}
		if m, err := parseSumsDigest(sums, deb); err == nil {
			st.SHA256 = m
		}
		if src, err := os.ReadFile(filepath.Join(s.o.Dir, e.Name(), sourceFile)); err == nil {
			st.Source = strings.TrimSpace(string(src))
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := ParseVersion(out[i].Version)
		b, _ := ParseVersion(out[j].Version)
		return a.Compare(b) > 0
	})
	return out
}

// --- helper results ---

// Reconcile reports the outcome of the last update, if the helper left one:
// audit entry "update.apply", result moved to last-result.json, the staged
// bundle removed. Run calls it on start and every few seconds, because the
// helper finishes after the new hub has already started. It returns the
// result it reported, or nil.
func (s *Service) Reconcile(ctx context.Context) (*Result, error) {
	path := filepath.Join(s.o.Dir, ResultFile)
	var res Result
	err := readJSON(path, MaxResultBytes, &res)
	switch {
	case err == nil:
	case isNotExist(err):
		return nil, nil
	default:
		// Unreadable or corrupt: report it once instead of looping forever.
		res = Result{Status: StatusError, Message: "the update helper left an unreadable result file: " + err.Error(), FinishedAt: s.now()}
	}
	switch res.Status {
	case StatusOK, StatusRolledBack, StatusError:
	default:
		res.Status = StatusError
	}
	// last-result.json holds what was reported (normalized), not the raw file.
	if err := writeJSONAtomic(s.o.Dir, LastResultFile, res, 0o600); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !isNotExist(err) {
		return nil, err
	}
	_ = os.Remove(filepath.Join(s.o.Dir, ApplyingFile))
	if v, err := ParseVersion(res.Version); err == nil && v.String() == res.Version {
		_ = os.RemoveAll(filepath.Join(s.o.Dir, res.Version))
	}
	detail := fmt.Sprintf("%s -> %s: %s", orStr(res.PreviousVersion, "?"), orStr(res.Version, "?"), res.Status)
	var aerr error
	if res.Status != StatusOK {
		aerr = errors.New(res.Message)
	}
	s.audit(ctx, res.RequestedBy, ActionApply, detail, aerr)
	s.mu.Lock()
	s.check = nil // current version changed (or the answer is stale); check again soon
	s.mu.Unlock()
	return &res, nil
}

// cleanup removes leftovers of interrupted staging.
func (s *Service) cleanup() {
	entries, err := os.ReadDir(s.o.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".incoming-") && !strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		if fi, err := e.Info(); err == nil && s.now().Sub(fi.ModTime()) > time.Hour {
			_ = os.RemoveAll(filepath.Join(s.o.Dir, e.Name()))
		}
	}
}
