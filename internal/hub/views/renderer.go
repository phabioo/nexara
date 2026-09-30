// Package views renders the Nexus UI: it parses the embedded layouts, partials and pages once and
// executes them into a buffer, so a failing template never produces a half-written response.
package views

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
)

// Options configure a Renderer.
type Options struct {
	// StaticBase is the URL prefix of the static files, with trailing slash. Default "/static/".
	StaticBase string
	// InlineSprite, when set, is inserted by {{sprite}} at the top of <body> and icons reference it
	// with "#i-name" instead of the sprite URL. Used by the static preview.
	InlineSprite string
}

type page struct {
	tmpl   *template.Template
	layout string
}

// Renderer executes page templates and HTMX fragments.
type Renderer struct {
	opts Options

	mu    sync.RWMutex
	base  *template.Template // layouts + partials, never executed
	frag  *template.Template // clone of base for RenderPartial
	pages map[string]page
}

// New parses layouts/*.html and partials/*.html from fsys (web.Templates) and every pages/*.html
// as its own template set. A page may select its layout with {{define "layout"}}auth{{end}};
// the default layout is "app".
func New(fsys fs.FS, opts Options) (*Renderer, error) {
	if opts.StaticBase == "" {
		opts.StaticBase = "/static/"
	}
	if !strings.HasSuffix(opts.StaticBase, "/") {
		opts.StaticBase += "/"
	}
	r := &Renderer{opts: opts, pages: map[string]page{}}

	var shared []string
	for _, dir := range []string{"layouts", "partials"} {
		files, err := fs.Glob(fsys, dir+"/*.html")
		if err != nil {
			return nil, err
		}
		shared = append(shared, files...)
	}
	if len(shared) == 0 {
		return nil, fmt.Errorf("views: no layouts or partials found")
	}
	base, err := template.New("base").Funcs(r.funcMap()).ParseFS(fsys, shared...)
	if err != nil {
		return nil, fmt.Errorf("views: parse shared templates: %w", err)
	}
	r.base = base
	if r.frag, err = base.Clone(); err != nil {
		return nil, err
	}

	pages, err := fs.Glob(fsys, "pages/*.html")
	if err != nil {
		return nil, err
	}
	for _, file := range pages {
		src, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(path.Base(file), ".html")
		if err := r.AddPage(name, string(src)); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// AddPage registers a page from template source. Used by New for pages/*.html and by the preview tool.
func (r *Renderer) AddPage(name, source string) error {
	t, err := r.base.Clone()
	if err != nil {
		return err
	}
	if _, err := t.New(name + ".html").Parse(source); err != nil {
		return fmt.Errorf("views: parse page %s: %w", name, err)
	}
	layout := "app"
	if t.Lookup("layout") != nil {
		var b bytes.Buffer
		if err := t.ExecuteTemplate(&b, "layout", nil); err != nil {
			return fmt.Errorf("views: page %s: layout: %w", name, err)
		}
		layout = strings.TrimSpace(b.String())
	}
	if t.Lookup(layout) == nil {
		return fmt.Errorf("views: page %s: unknown layout %q", name, layout)
	}
	r.mu.Lock()
	r.pages[name] = page{tmpl: t, layout: layout}
	r.mu.Unlock()
	return nil
}

// Render executes the page (for example "overview") inside its layout. Nothing is written to w on error.
func (r *Renderer) Render(w http.ResponseWriter, name string, data any) error {
	r.mu.RLock()
	p, ok := r.pages[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("views: unknown page %q", name)
	}
	var buf bytes.Buffer
	if err := p.tmpl.ExecuteTemplate(&buf, p.layout, data); err != nil {
		return fmt.Errorf("views: render page %s: %w", name, err)
	}
	return write(w, &buf)
}

// RenderPartial executes a named template of partials/ (an HTMX fragment) without any layout.
func (r *Renderer) RenderPartial(w http.ResponseWriter, name string, data any) error {
	var buf bytes.Buffer
	if err := r.frag.ExecuteTemplate(&buf, name, data); err != nil {
		return fmt.Errorf("views: render partial %s: %w", name, err)
	}
	return write(w, &buf)
}

func write(w http.ResponseWriter, buf *bytes.Buffer) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write(buf.Bytes())
	return err
}
