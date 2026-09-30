// Command preview renders the UI foundation to static HTML files so the layouts can be checked in a
// browser without a running hub:
//
//	go run ./internal/hub/views/cmd/preview -out .preview
//
// The files link CSS and JS through a relative path into web/static and inline the icon sprite, so they
// also work from file://. The data is the pi5-media sample from the design screenshots.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/web"
)

//go:embed pages/*.html
var previewPages embed.FS

type core struct {
	Label string
	Pct   int
}

type service struct {
	Name, State string
	Bad         bool
}

type filter struct {
	Label  string
	Count  int
	Active bool
}

type pkg struct {
	Tone, Glyph, Label, Name, Desc, Ver, Size, Action, ActionClass string
}

type appData struct {
	views.Layout
	Cores                []core
	Services             []service
	Filters              []filter
	PkgList              []pkg
	CurveLine, CurveArea string
}

type authData struct {
	views.AuthLayout
	Steps views.SetupSteps
}

func main() {
	out := flag.String("out", "", "output directory (required)")
	flag.Parse()
	if *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*out); err != nil {
		log.Fatal(err)
	}
}

func run(out string) error {
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return err
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(outAbs, filepath.Join(root, "web", "static"))
	if err != nil {
		return fmt.Errorf("static directory is not reachable from %s: %w", outAbs, err)
	}
	sprite, err := fs.ReadFile(web.Static, "img/icons.svg")
	if err != nil {
		return err
	}
	r, err := views.New(web.Templates, views.Options{
		StaticBase:   filepath.ToSlash(rel) + "/",
		InlineSprite: string(sprite),
	})
	if err != nil {
		return err
	}
	entries, err := previewPages.ReadDir("pages")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		src, err := previewPages.ReadFile("pages/" + e.Name())
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(e.Name(), ".html")
		if err := r.AddPage(name, string(src)); err != nil {
			return err
		}
		names = append(names, name)
	}

	for _, name := range names {
		data := any(appData0(name))
		if name == "login" || name == "setup" {
			data = authData0(name)
		}
		rec := httptest.NewRecorder()
		if err := r.Render(rec, name, data); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outAbs, name+".html"), rec.Body.Bytes(), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", filepath.Join(outAbs, name+".html"))
	}
	var idx strings.Builder
	idx.WriteString("<!doctype html><meta charset=utf-8><title>Nexus preview</title><body style=\"font-family:monospace;background:#111;color:#eee\"><ul>")
	for _, n := range names {
		fmt.Fprintf(&idx, "<li><a style=\"color:#c6f500\" href=\"%s.html\">%s</a></li>", n, n)
	}
	idx.WriteString("</ul>")
	return os.WriteFile(filepath.Join(outAbs, "index.html"), []byte(idx.String()), 0o644)
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above the working directory")
		}
		dir = parent
	}
}

func appData0(page string) appData {
	l := views.Layout{
		Title:     "Overview",
		ActiveNav: "overview",
		CSRF:      "preview",
		Operator:  "fabio",
		NodeNo:    "01",
		Uptime:    "41D 06H",
		HostName:  "pi5-media",
		HostIP:    "192.168.10.21",
		Online:    2,
		Packages:  "7/10",
		Temp:      "47.2",
		Latency:   "4 ms",
		Hosts: []views.HostTab{
			{Name: "pi5-media", Href: "#pi5", Active: true, Badge: 3},
			{Name: "pi3-dns", Href: "#pi3", Badge: 2},
		},
		Nav:        views.DefaultNav(3),
		AddHostURL: "#add",
		Log:        "Connected to pi5-media",
		Toast:      &views.Toast{Title: "Updated", Sub: "3 packages upgraded"},
	}
	if page == "packages" {
		l.Title, l.ActiveNav = "Packages", "packages"
	}
	d := appData{Layout: l}
	for i, p := range []int{28, 20, 25, 22} {
		d.Cores = append(d.Cores, core{Label: fmt.Sprintf("Core %d", i), Pct: p})
	}
	d.Services = []service{
		{"ssh", "active", false}, {"plexmediaserver", "active", false}, {"docker", "active", false},
		{"cron", "active", false}, {"smbd", "failed", true}, {"avahi-daemon", "active", false},
	}
	d.Filters = []filter{{"All", 12, true}, {"Updates", 3, false}, {"Installed", 10, false}, {"Available", 0, false}, {"Orphaned", 2, false}}
	upd := "btn-tool is-hot"
	d.PkgList = []pkg{
		{"lime", "arrow-up", "Update", "openssh-server", "Secure shell server", "1:9.2p1-2+deb12u3 → 1:9.2p1-2+deb12u4", "1.4 MB", "Update", upd},
		{"lime", "arrow-up", "Update", "linux-image-rpi-v8", "Raspberry Pi kernel (arm64)", "6.6.51-1+rpt3 → 6.6.62-1+rpt1", "78 MB", "Update", upd},
		{"lime", "arrow-up", "Update", "ffmpeg", "Audio and video tools", "7:5.1.6-0+deb12u1 → 7:5.1.7-0+deb12u1", "9.6 MB", "Update", upd},
		{"grey", "check", "Installed", "curl", "Command-line URL client", "7.88.1-10+deb12u8", "315 KB", "Remove", ""},
		{"grey", "check", "Installed", "htop", "Interactive process viewer", "3.2.2-2", "432 KB", "Remove", ""},
		{"grey", "check", "Installed", "nginx", "Web server and reverse proxy", "1.22.1-9", "1.6 MB", "Remove", ""},
		{"grey", "check", "Installed", "docker.io", "Container runtime", "20.10.24+dfsg1-1", "31 MB", "Remove", ""},
		{"grey", "check", "Installed", "etherwake", "Wake-on-LAN client", "1.09-4+b1", "22 KB", "Remove", ""},
		{"grey", "check", "Installed", "samba", "SMB/CIFS file server", "2:4.17.12+dfsg-0+deb12u1", "3.1 MB", "Remove", ""},
		{"grey", "check", "Installed", "python3-pip", "Python package installer", "23.0.1+dfsg-1", "1.3 MB", "Remove", ""},
		{"pink", "close", "Orphaned", "linux-image-6.1.0-rpi7", "Old kernel, no longer needed", "6.1.63-1+rpt1", "64 MB", "Remove", ""},
		{"pink", "close", "Orphaned", "libjs-sphinxdoc", "Orphaned dependency", "5.3.0-4", "1.1 MB", "Remove", ""},
	}
	var line, area strings.Builder
	area.WriteString("0,100 ")
	for i := 0; i < 48; i++ {
		x := float64(i) * 300 / 47
		y := 72 - 10*math.Sin(float64(i)/5) - 6*math.Sin(float64(i)/2.3)
		fmt.Fprintf(&line, "%.1f,%.1f ", x, y)
		fmt.Fprintf(&area, "%.1f,%.1f ", x, y)
	}
	area.WriteString("300,100")
	d.CurveLine, d.CurveArea = strings.TrimSpace(line.String()), area.String()
	return d
}

func authData0(page string) authData {
	d := authData{AuthLayout: views.AuthLayout{
		Title:     "Sign in",
		CSRF:      "preview",
		BodyClass: "",
		Variant:   "auth-login",
		Segments:  []views.PillSegment{{Text: "LOCKED", Icon: "lock"}},
		MicroLines: []string{"[nexara nexus standby]", "operator authentication required",
			"grid nodes . . . . . . . [locked]"},
		BuildLines: []string{"nexus build 0.1.0", "go1.26 · linux/arm64"},
		Log:        "Awaiting operator credentials",
		LiveText:   "SECURE CHANNEL · TLS 1.3",
	}}
	if page == "setup" {
		d.Title = "Setup"
		d.Variant = "auth-setup"
		d.Segments = []views.PillSegment{{Text: "SETUP"}, {Text: "1/7", Light: true}}
		d.MicroLines = []string{"[nexara nexus first run]", "hub not claimed · setup mode active", "grid nodes . . . . . . . [none]"}
		d.Log = "Waiting for the setup code"
		d.LiveText = "SETUP MODE · LAN ONLY"
		d.Steps = views.NewSetupSteps([]string{"Unlock", "Trust", "Operator", "Two-factor", "Hub", "Self-link", "Ready"}, 1)
	}
	return d
}
