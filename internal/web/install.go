package web

import (
	"net/http"
	"strings"

	"github.com/JeffResc/AuthStep/internal/store"
)

// detectOS guesses the visitor's platform from the User-Agent so the
// matching install guide opens first. iPadOS Safari reports itself as macOS
// by default, so iPads get the macOS guide opened; the iPhone and iPad guide
// is always one click away.
func detectOS(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ipod"):
		return "ios"
	case strings.Contains(ua, "android"):
		return "android"
	case strings.Contains(ua, "windows"):
		return "windows"
	case strings.Contains(ua, "macintosh"), strings.Contains(ua, "mac os x"):
		return "macos"
	case strings.Contains(ua, "linux"), strings.Contains(ua, "x11"), strings.Contains(ua, "cros"):
		return "linux"
	}
	return ""
}

// deviceExample is the example device name shown in the name fields,
// matched to the visitor's device.
func deviceExample(ua string) string {
	switch detectOS(ua) {
	case "ios":
		if strings.Contains(strings.ToLower(ua), "ipad") {
			return "Personal iPad"
		}
		return "Personal iPhone"
	case "macos":
		return "Personal MacBook"
	case "android":
		return "Personal Phone"
	}
	return "Personal Computer"
}

func (s *Server) installHelp(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "install", newPageData(r, "Install a certificate"))
}

type handoffView struct {
	URL string
	QR  any
}

// handoff shows a QR code for the start page so a user can open AuthStep on
// another device and sign in there, where that device creates its own key.
func (s *Server) handoff(w http.ResponseWriter, r *http.Request, _ store.User) {
	url := s.baseURL + "/"
	svg, err := qrSVG(url)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := newPageData(r, "Set up another device")
	d.View = handoffView{URL: url, QR: svg}
	s.render(w, http.StatusOK, "handoff", d)
}
