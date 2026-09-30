// Package web embeds the static assets and HTML templates of the Nexus UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static templates
var assets embed.FS

var (
	// Static holds the files served under /static/ (CSS, JS, fonts, images), rooted at web/static.
	Static = mustSub("static")
	// Templates holds layouts/, partials/ and pages/, rooted at web/templates.
	Templates = mustSub("templates")
)

func mustSub(dir string) fs.FS {
	sub, err := fs.Sub(assets, dir)
	if err != nil {
		panic("web: embedded directory " + dir + ": " + err.Error())
	}
	return sub
}
