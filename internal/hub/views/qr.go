package views

import (
	"errors"
	"fmt"
	"html"
	"html/template"
	"strings"

	"github.com/boombuler/barcode/qr"
)

// QRLevel is the error correction level of a QR code. Lower levels give a
// smaller, easier to scan code for the same content.
type QRLevel int

// Error correction levels (about 7, 15, 25 and 30 percent recoverable).
const (
	QRLow QRLevel = iota
	QRMedium
	QRQuartile
	QRHigh
)

// qrMaxContent bounds the input so a caller bug cannot produce a huge SVG.
const qrMaxContent = 1024

// qrQuiet is the quiet zone in modules. The standard asks for 4; 2 scans
// reliably on screens, where the code sits on a light panel anyway.
const qrQuiet = 2

// QRSVG renders content as a QR code in an inline SVG (decision #32): one path
// for all dark modules on a light background, sized by CSS (width/height) and
// with crisp edges. It uses presentation attributes only, so it works under a
// strict CSP (no inline style, no data: URI). label becomes the accessible
// name of the image.
//
// The output is safe to embed unescaped: it is built from numbers and the
// escaped label only.
func QRSVG(content string, level QRLevel, label string) (template.HTML, error) {
	if content == "" {
		return "", errors.New("views: QR content is empty")
	}
	if len(content) > qrMaxContent {
		return "", fmt.Errorf("views: QR content too long (%d bytes, max %d)", len(content), qrMaxContent)
	}
	var ecc qr.ErrorCorrectionLevel
	switch level {
	case QRLow:
		ecc = qr.L
	case QRQuartile:
		ecc = qr.Q
	case QRHigh:
		ecc = qr.H
	default:
		ecc = qr.M
	}
	code, err := qr.Encode(content, ecc, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("views: encode QR: %w", err)
	}
	b := code.Bounds()
	n := b.Dx()
	if n <= 0 || b.Dy() != n {
		return "", errors.New("views: QR code is not square")
	}

	var path strings.Builder
	for y := 0; y < n; y++ {
		for x := 0; x < n; {
			if !dark(code.At(b.Min.X+x, b.Min.Y+y)) {
				x++
				continue
			}
			start := x
			for x < n && dark(code.At(b.Min.X+x, b.Min.Y+y)) {
				x++
			}
			// Horizontal run of dark modules: move, then h/v/h/z.
			fmt.Fprintf(&path, "M%d %dh%dv1h-%dz", start+qrQuiet, y+qrQuiet, x-start, x-start)
		}
	}

	size := n + 2*qrQuiet
	var out strings.Builder
	fmt.Fprintf(&out,
		`<svg class="qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %[1]d %[1]d" role="img" aria-label="%[2]s" shape-rendering="crispEdges" focusable="false">`,
		size, html.EscapeString(label))
	fmt.Fprintf(&out, `<rect width="%[1]d" height="%[1]d" fill="#f2f3ef"/>`, size)
	fmt.Fprintf(&out, `<path fill="#0d0e0f" d="%s"/></svg>`, path.String())
	return template.HTML(out.String()), nil //nolint:gosec // numbers and an escaped label only
}

// dark reports whether a barcode pixel is a dark module. barcode/qr returns
// color.Gray16 values: black (0) for dark, white for light.
func dark(c interface{ RGBA() (r, g, b, a uint32) }) bool {
	r, _, _, _ := c.RGBA()
	return r < 0x8000
}
