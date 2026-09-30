// Package agentbin holds the Grid Agent binaries embedded in the hub (decision
// #20). The release build (scripts/build.sh) compiles the agents first and
// places them in bin/ as grid-agent_<os>_<arch>; a plain `go build` embeds an
// empty directory and Lookup then reports ok=false.
package agentbin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"strings"
	"sync"

	"github.com/phabioo/nexara/internal/buildinfo"
)

//go:embed all:bin
var files embed.FS

// Binary is one embedded agent build.
type Binary struct {
	OS, Arch string
	Version  string // the hub's own version; agents are built from the same tag
	SHA256   string // lower-case hex
	Data     []byte
}

var (
	mu    sync.Mutex
	cache = map[string]Binary{}
)

// Lookup returns the agent binary for goos/goarch.
func Lookup(goos, goarch string) (Binary, bool) {
	name := "grid-agent_" + goos + "_" + goarch
	mu.Lock()
	defer mu.Unlock()
	if b, ok := cache[name]; ok {
		return b, true
	}
	data, err := fs.ReadFile(files, "bin/"+name)
	if err != nil || len(data) == 0 {
		return Binary{}, false
	}
	sum := sha256.Sum256(data)
	b := Binary{OS: goos, Arch: goarch, Version: buildinfo.Version, SHA256: hex.EncodeToString(sum[:]), Data: data}
	cache[name] = b
	return b, true
}

// Available lists the embedded os/arch pairs as "os/arch".
func Available() []string {
	entries, _ := fs.ReadDir(files, "bin")
	var out []string
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), "grid-agent_")
		if !ok {
			continue
		}
		if goos, goarch, ok := strings.Cut(rest, "_"); ok && goos != "" && goarch != "" {
			out = append(out, goos+"/"+goarch)
		}
	}
	return out
}
