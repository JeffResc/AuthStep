package web

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/scep"
	"github.com/JeffResc/AuthStep/internal/store"
)

// appleView drives apple.html. Mode is "handoff" (on a non-Apple device:
// show a QR code), "form" (name the device), "download" or "downloaded".
type appleView struct {
	Mode       string
	ID         string
	DeviceName string
	QR         any
	URL        string
	InstallBy  string
}

// appleForm starts an Apple enrolment. The profile must be downloaded on the
// device that gets the certificate, so other devices see a QR code first.
func (s *Server) appleForm(w http.ResponseWriter, r *http.Request, _ store.User) {
	d := newPageData(r, "Add Apple device")
	onApple := d.OS == "ios" || d.OS == "macos"
	if !onApple && r.URL.Query().Get("here") == "" {
		pageURL := s.baseURL + "/certs/apple"
		svg, err := qrSVG(pageURL)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.View = appleView{Mode: "handoff", QR: svg, URL: pageURL}
	} else {
		d.View = appleView{Mode: "form"}
	}
	s.render(w, http.StatusOK, "apple", d)
}

func (s *Server) appleReserve(w http.ResponseWriter, r *http.Request, user store.User) {
	res, err := s.certs.Reserve(r.Context(), user, r.PostFormValue("deviceName"), "scep")
	switch {
	case errors.Is(err, certs.ErrInvalidDeviceName):
		s.renderError(w, r, http.StatusBadRequest, "Device name must be 1 to 64 printable characters.")
	case errors.Is(err, store.ErrLimitReached):
		s.renderError(w, r, http.StatusConflict, "You have reached your certificate limit. Revoke a certificate you no longer use, or ask an administrator to raise your limit.")
	case err != nil:
		s.fail(w, r, err)
	default:
		http.Redirect(w, r, "/certs/"+url.PathEscape(res.ID)+"/apple", http.StatusSeeOther)
	}
}

func (s *Server) appleReady(w http.ResponseWriter, r *http.Request, user store.User) {
	c, err := s.store.UserCertificate(r.Context(), user.Sub, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "Request not found.")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	case c.Method != "scep" || c.Status != "pending":
		s.renderError(w, r, http.StatusConflict, "This request was already used. Start again to add another device.")
		return
	}
	expires, downloaded, err := s.store.SCEPChallengeExpiry(r.Context(), c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := appleView{Mode: "download", ID: c.ID, DeviceName: c.DeviceName}
	if downloaded {
		left := time.Until(expires)
		if left <= 0 {
			s.renderError(w, r, http.StatusConflict, "This profile expired before it was installed. Start again to add the device.")
			return
		}
		v.Mode, v.InstallBy = "downloaded", minutesLeft(left)
	}
	d := newPageData(r, "Install profile")
	d.View = v
	s.render(w, http.StatusOK, "apple", d)
}

// appleProfile serves the signed profile. It holds a one-time challenge, so
// it can be downloaded once.
func (s *Server) appleProfile(w http.ResponseWriter, r *http.Request, user store.User) {
	profile, err := s.scep.Profile(r.Context(), user, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "Request not found.")
	case errors.Is(err, store.ErrChallengeExists), errors.Is(err, scep.ErrNotSCEP):
		s.renderError(w, r, http.StatusConflict, "This profile was already downloaded. Start again to add another device.")
	case errors.Is(err, certs.ErrReservationExpired):
		s.renderError(w, r, http.StatusConflict, "This request expired. Start again.")
	case err != nil:
		s.fail(w, r, err)
	default:
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="authstep.mobileconfig"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(profile)
	}
}
