package views

import (
	"fmt"
	"html/template"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// iconSizes holds the native size of every symbol in web/static/img/icons.svg (its viewBox).
var iconSizes = map[string][2]int{
	"mark":          {64, 64},
	"reboot":        {14, 14},
	"power":         {14, 14},
	"info":          {14, 14},
	"arrow-right":   {16, 12},
	"arrow-up":      {12, 12},
	"plus":          {12, 12},
	"close":         {12, 12},
	"check":         {12, 12},
	"thermometer":   {14, 14},
	"list":          {14, 14},
	"package":       {18, 18},
	"terminal":      {18, 18},
	"warning":       {18, 18},
	"dots":          {18, 18},
	"eye":           {18, 14},
	"lock":          {14, 14},
	"sign-out":      {14, 14},
	"history":       {18, 18},
	"settings":      {16, 16},
	"chevron-right": {10, 14},
	"overview":      {18, 18},
	"copy":          {14, 14},
	"circle":        {18, 18},
	"database":      {12, 12},
}

// funcMap returns the template functions. The renderer options decide where assets and icons live.
func (r *Renderer) funcMap() template.FuncMap {
	return template.FuncMap{
		"bytes":    formatBytes,
		"percent":  formatPercent,
		"duration": formatDuration,
		"upper":    strings.ToUpper,
		"seq":      seq,
		"pct":      pctClass,
		"odd":      func(i int) bool { return i%2 != 0 },
		"dict":     dict,
		"has":      has,
		"attr":     attr,
		"icon":     r.icon,
		"static":   r.static,
		"sprite":   r.sprite,
	}
}

func (r *Renderer) static(p string) string {
	return r.opts.StaticBase + strings.TrimPrefix(p, "/")
}

// sprite returns the inline sprite (preview and tests) or nothing when icons are loaded from the static path.
func (r *Renderer) sprite() template.HTML {
	return template.HTML(r.opts.InlineSprite) //nolint:gosec // trusted, comes from the embedded sprite file
}

// icon renders an <svg><use> reference to a symbol of the sprite. The optional size is the width in px;
// the height follows the native aspect ratio.
func (r *Renderer) icon(name string, size ...int) (template.HTML, error) {
	native, ok := iconSizes[name]
	if !ok {
		return "", fmt.Errorf("unknown icon %q", name)
	}
	w, h := native[0], native[1]
	if len(size) > 0 && size[0] > 0 {
		h = int(math.Round(float64(size[0]) * float64(native[1]) / float64(native[0])))
		w = size[0]
	}
	href := "#i-" + name
	if r.opts.InlineSprite == "" {
		href = r.opts.StaticBase + "img/icons.svg#i-" + name
	}
	return template.HTML(fmt.Sprintf(
		`<svg class="icon" width="%d" height="%d" aria-hidden="true" focusable="false"><use href="%s"></use></svg>`,
		w, h, template.HTMLEscapeString(href))), nil
}

// attr builds a template.HTMLAttr for the Attrs parameters of the component templates:
// {{attr "data-modal-close"}} for a bare attribute, or name/value pairs like
// {{attr "hx-get" "/x" "hx-target" "#modal-root"}}. html/template rejects a plain string in attribute
// position (it renders ZgotmplZ), so templates must go through this or pass an HTMLAttr from Go.
// Names must be plain attribute names (no event handlers); values are escaped.
func attr(args ...string) (template.HTMLAttr, error) {
	if len(args) == 1 {
		if err := checkAttrName(args[0]); err != nil {
			return "", err
		}
		return template.HTMLAttr(args[0]), nil //nolint:gosec // name matched the allowlist
	}
	if len(args) == 0 || len(args)%2 != 0 {
		return "", fmt.Errorf("attr: want one name or name/value pairs, got %d arguments", len(args))
	}
	var b strings.Builder
	for i := 0; i < len(args); i += 2 {
		if err := checkAttrName(args[i]); err != nil {
			return "", err
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(args[i] + `="` + template.HTMLEscapeString(args[i+1]) + `"`)
	}
	return template.HTMLAttr(b.String()), nil //nolint:gosec // names matched the allowlist, values are escaped
}

func checkAttrName(name string) error {
	if !attrNameRE.MatchString(name) || strings.HasPrefix(strings.ToLower(name), "on") {
		return fmt.Errorf("attr: unsafe attribute name %q", name)
	}
	return nil
}

var attrNameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_:-]*$`)

// toFloat converts any Go number to float64.
func toFloat(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

// formatBytes renders a byte count with binary units: 3.4 GB, 117 GB, 4 TB, 512 B.
func formatBytes(v any) (string, error) {
	f, ok := toFloat(v)
	if !ok {
		return "", fmt.Errorf("bytes: unsupported type %T", v)
	}
	if f < 0 || math.IsNaN(f) {
		f = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return strconv.FormatInt(int64(f), 10) + " B", nil
	}
	s := strconv.FormatFloat(f, 'f', 1, 64)
	if f >= 9.95 { // one decimal would round to two digits, drop it
		s = strconv.FormatFloat(f, 'f', 0, 64)
	}
	s = strings.TrimSuffix(s, ".0")
	return s + " " + units[i], nil
}

// formatPercent renders a percentage value (0-100) as "24%".
func formatPercent(v any) (string, error) {
	f, ok := toFloat(v)
	if !ok {
		return "", fmt.Errorf("percent: unsupported type %T", v)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		f = 0
	}
	return strconv.FormatFloat(math.Round(f), 'f', 0, 64) + "%", nil
}

// formatDuration renders an uptime: "41D 06H", "06H 12M" or "12M 30S". Plain numbers are seconds,
// a time.Duration keeps its own unit.
func formatDuration(v any) (string, error) {
	var secs int64
	switch d := v.(type) {
	case time.Duration:
		secs = int64(d / time.Second)
	default:
		f, ok := toFloat(v)
		if !ok {
			return "", fmt.Errorf("duration: unsupported type %T", v)
		}
		secs = int64(f)
	}
	if secs < 0 {
		secs = 0
	}
	days, hours, mins := secs/86400, secs%86400/3600, secs%3600/60
	switch {
	case days > 0:
		return fmt.Sprintf("%dD %02dH", days, hours), nil
	case hours > 0:
		return fmt.Sprintf("%02dH %02dM", hours, mins), nil
	default:
		return fmt.Sprintf("%02dM %02dS", mins, secs%60), nil
	}
}

// seq returns 0..n-1, for pixel cells and tickers: {{range $i := seq 16}}.
func seq(n int) []int {
	if n < 0 || n > 4096 {
		return nil
	}
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}

// pctClass returns the CSS class that sets a bar fill width, "p-0" to "p-100" (values are clamped).
func pctClass(v any) string {
	f, ok := toFloat(v)
	if !ok || math.IsNaN(f) {
		return "p-0"
	}
	n := int(math.Round(math.Max(0, math.Min(100, f))))
	return "p-" + strconv.Itoa(n)
}

// dict builds a map for component templates: {{template "tag" (dict "Tone" "lime" "Text" "Live")}}.
func dict(pairs ...any) (map[string]any, error) {
	if len(pairs)%2 != 0 {
		return nil, fmt.Errorf("dict: odd number of arguments")
	}
	m := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %v is not a string", pairs[i])
		}
		m[k] = pairs[i+1]
	}
	return m, nil
}

// has reports whether a value is worth rendering: not nil and not an empty string. Zero numbers count.
func has(v any) bool {
	if v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return s != ""
	}
	return true
}
