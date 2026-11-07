package web

import (
	"fmt"
	"html/template"
	"strings"

	"rsc.io/qr"
)

// quietZone is the blank border, in modules, that scanners need around a code.
const quietZone = 4

// qrSVG renders text as an inline SVG QR code. It is always black on white,
// whatever the page theme, because scanners expect dark modules on light.
func qrSVG(text string) (template.HTML, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	var path strings.Builder
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quietZone, y+quietZone)
			}
		}
	}
	n := code.Size + 2*quietZone
	// The SVG holds only numbers we generated, so it is safe as HTML.
	return template.HTML(fmt.Sprintf(
		`<svg class="qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="QR code for %s" shape-rendering="crispEdges">`+
			`<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>`,
		n, n, template.HTMLEscapeString(text), n, n, path.String())), nil
}
