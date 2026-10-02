package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// The hub's only outbound connection (decision #53), opt-in.
const (
	githubRepo         = "phabioo/nexara"
	defaultAPIBase     = "https://api.github.com"
	defaultDownloadURL = "https://github.com"

	maxAPIBytes      = 2 << 20
	maxNotesBytes    = 4 << 10
	maxRedirects     = 5
	apiTimeout       = 20 * time.Second
	downloadTimeout  = 15 * time.Minute
	releasesPerCheck = 30
)

// githubHosts are the only hosts a request or a redirect may reach. GitHub
// serves release assets from its object storage hosts; the name changed over
// time, so both known ones are listed.
var githubHosts = []string{
	"api.github.com",
	"github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
}

var tagRe = regexp.MustCompile(`^v` + versionPattern + `$`)

// Release is the newest release that fits the channel and has a package for
// this machine.
type Release struct {
	Tag         string    `json:"tag"`
	Version     string    `json:"version"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	URL         string    `json:"url"`   // release page, for the operator
	Notes       string    `json:"notes"` // plain text, truncated; escape when rendering
}

type apiRelease struct {
	TagName     string    `json:"tag_name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

// githubClient talks to GitHub Releases with a fixed host allow-list.
type githubClient struct {
	http         *http.Client
	apiBase      string
	downloadBase string
	hosts        map[string]bool
	userAgent    string
}

func newGitHubClient(o Options, base *http.Client) *githubClient {
	g := &githubClient{
		apiBase:      strings.TrimRight(orStr(o.APIBase, defaultAPIBase), "/"),
		downloadBase: strings.TrimRight(orStr(o.DownloadBase, defaultDownloadURL), "/"),
		hosts:        map[string]bool{},
		userAgent:    "nexara-nexus/" + o.CurrentVersion,
	}
	for _, h := range githubHosts {
		g.hosts[h] = true
	}
	for _, h := range o.AllowedHosts {
		g.hosts[h] = true
	}
	c := *base
	c.CheckRedirect = g.checkRedirect
	g.http = &c
	return g
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// defaultHTTPClient uses the system roots and the usual proxy variables; no
// client certificates, no cookies.
func defaultHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		DisableKeepAlives:     true,
	}}
}

func (g *githubClient) checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("update: refusing non-HTTPS URL for host %q", u.Hostname())
	}
	if !g.hosts[u.Hostname()] {
		return fmt.Errorf("update: refusing host %q (only GitHub is allowed)", u.Hostname())
	}
	return nil
}

func (g *githubClient) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("update: too many redirects")
	}
	return g.checkURL(req.URL)
}

func (g *githubClient) get(ctx context.Context, rawURL string, timeout time.Duration, accept string) (*http.Response, context.CancelFunc, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if err := g.checkURL(u); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header.Set("User-Agent", g.userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := g.http.Do(req)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("update: GitHub request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, nil, fmt.Errorf("update: GitHub answered %s", resp.Status)
	}
	return resp, cancel, nil
}

// latest returns the newest non-draft release of the channel ("stable": no
// pre-releases; "rc": pre-releases count) that carries the package for arch
// and the signed sums. Releases without them are skipped (an upload may still
// be running).
func (g *githubClient) latest(ctx context.Context, channel, arch string) (Release, bool, error) {
	resp, cancel, err := g.get(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=%d", g.apiBase, githubRepo, releasesPerCheck),
		apiTimeout, "application/vnd.github+json")
	if err != nil {
		return Release{}, false, err
	}
	defer cancel()
	defer resp.Body.Close()
	body, err := readAllLimited(resp.Body, maxAPIBytes)
	if err != nil {
		return Release{}, false, fmt.Errorf("update: reading GitHub answer: %w", err)
	}
	var list []apiRelease
	if err := json.Unmarshal(body, &list); err != nil {
		return Release{}, false, fmt.Errorf("update: decoding GitHub answer: %w", err)
	}

	var best Release
	var bestV Version
	found := false
	for _, r := range list {
		if r.Draft || !tagRe.MatchString(r.TagName) {
			continue
		}
		v, err := ParseVersion(r.TagName)
		if err != nil {
			continue
		}
		if channel != ChannelRC && (r.Prerelease || v.IsPrerelease()) {
			continue
		}
		if !hasAssets(r, DebName(v.String(), arch), SumsFile, SigFile) {
			continue
		}
		if found && v.Compare(bestV) <= 0 {
			continue
		}
		notes := r.Body
		if len(notes) > maxNotesBytes {
			notes = notes[:maxNotesBytes]
		}
		best, bestV, found = Release{
			Tag: r.TagName, Version: v.String(), Prerelease: r.Prerelease || v.IsPrerelease(),
			PublishedAt: r.PublishedAt,
			URL:         "https://github.com/" + githubRepo + "/releases/tag/" + r.TagName,
			Notes:       strings.ToValidUTF8(notes, ""),
		}, v, true
	}
	return best, found, nil
}

func hasAssets(r apiRelease, names ...string) bool {
	have := map[string]bool{}
	for _, a := range r.Assets {
		have[a.Name] = true
	}
	for _, n := range names {
		if !have[n] {
			return false
		}
	}
	return true
}

// download fetches one release asset into dst (created 0600). The URL is built
// here from the validated tag, never taken from the API answer.
func (g *githubClient) download(ctx context.Context, tag, asset, dst string, max int64) error {
	if !tagRe.MatchString(tag) {
		return fmt.Errorf("update: bad release tag %q", tag)
	}
	u := fmt.Sprintf("%s/%s/releases/download/%s/%s", g.downloadBase, githubRepo, tag, url.PathEscape(asset))
	resp, cancel, err := g.get(ctx, u, downloadTimeout, "application/octet-stream")
	if err != nil {
		return err
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.ContentLength > max {
		return fmt.Errorf("%w: %s", ErrTooLarge, asset)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("update: downloading %s: %w", asset, err)
	}
	if n > max {
		return fmt.Errorf("%w: %s", ErrTooLarge, asset)
	}
	return nil
}
