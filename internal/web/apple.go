package web

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/scep"
	"github.com/JeffResc/AuthStep/internal/store"
)

// appleView drives apple.html. Mode is "handoff" (on a non-Apple device:
// show a QR code), "form" (name the device), "download", "downloaded",
// "tvlink" (show a new Apple TV link) or "linked" (a link was shown before).
// TV is set while adding an Apple TV, which is set up from another device.
type appleView struct {
	Mode       string
	ID         string
	DeviceName string
	QR         any
	URL        string
	InstallBy  string
	TV         bool
	Code       string
}

// appleForm starts an Apple enrolment. The profile must be downloaded on the
// device that gets the certificate, so other devices see a QR code first.
func (s *Server) appleForm(w http.ResponseWriter, r *http.Request, _ store.User) {
	d := newPageData(r, "Add Apple device")
	onApple := d.OS == "ios" || d.OS == "macos"
	tv := r.URL.Query().Get("tv") != ""
	if !onApple && !tv && r.URL.Query().Get("here") == "" {
		pageURL := s.baseURL + "/certs/apple"
		svg, err := qrSVG(pageURL)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.View = appleView{Mode: "handoff", QR: svg, URL: pageURL}
	} else {
		d.View = appleView{Mode: "form", TV: tv}
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
		next := "/certs/" + url.PathEscape(res.ID) + "/apple"
		if r.PostFormValue("tv") != "" {
			next += "?tv=1"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
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
	v := appleView{Mode: "download", ID: c.ID, DeviceName: c.DeviceName, TV: r.URL.Query().Get("tv") != ""}
	linkExpires, linked, err := s.store.DeviceLinkExpiry(r.Context(), c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if linked && !downloaded {
		left := time.Until(linkExpires)
		if left <= 0 {
			s.renderError(w, r, http.StatusConflict, "The Apple TV link expired before it was used. Start again to add the device.")
			return
		}
		v.Mode, v.InstallBy = "linked", minutesLeft(left)
	}
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

// appleCancel cancels an Apple enrolment that has not enrolled yet. Its
// profile, if downloaded, can no longer enrol.
func (s *Server) appleCancel(w http.ResponseWriter, r *http.Request, user store.User) {
	c, err := s.store.CancelSCEPEnrolment(r.Context(), user.Sub, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "Request not found.")
		return
	case errors.Is(err, store.ErrNotPending):
		s.renderError(w, r, http.StatusConflict, "The device has already started enrolling. Revoke the certificate once it is active.")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	if err := s.audit.Record(r, actor(user), audit.CertCancelled, c.ID, map[string]any{"device": c.DeviceName}); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
		writeProfile(w, profile)
	}
}

// appleTVLink creates the one-time link an Apple TV types to fetch the
// profile, and shows it. The code cannot be shown again.
func (s *Server) appleTVLink(w http.ResponseWriter, r *http.Request, user store.User) {
	id := r.PathValue("id")
	code, expires, err := s.scep.CreateLink(r.Context(), user, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "Request not found.")
		return
	case errors.Is(err, store.ErrLinkExists):
		s.renderError(w, r, http.StatusConflict, "A link was already created for this request and is shown only once. Cancel the request and start again if you need a new link.")
		return
	case errors.Is(err, store.ErrChallengeExists), errors.Is(err, scep.ErrNotSCEP):
		s.renderError(w, r, http.StatusConflict, "This profile was already downloaded. Start again to add another device.")
		return
	case errors.Is(err, certs.ErrReservationExpired):
		s.renderError(w, r, http.StatusConflict, "This request expired. Start again.")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	c, err := s.store.UserCertificate(r.Context(), user.Sub, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := newPageData(r, "Apple TV link")
	d.View = appleView{Mode: "tvlink", ID: id, DeviceName: c.DeviceName, TV: true,
		Code: code, URL: s.baseURL + "/tv/" + code, InstallBy: minutesLeft(time.Until(expires))}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusOK, "apple", d)
}

// tvProfile serves the signed profile to the device that types a device
// link. It needs no session: the link is the credential, and works once.
func (s *Server) tvProfile(w http.ResponseWriter, r *http.Request) {
	profile, err := s.scep.ProfileByLink(r.Context(), r.PathValue("code"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "Link not found. Check the address.")
	case errors.Is(err, store.ErrLinkUsed), errors.Is(err, store.ErrLinkExpired), errors.Is(err, store.ErrNotPending),
		errors.Is(err, store.ErrChallengeExists), errors.Is(err, scep.ErrNotSCEP), errors.Is(err, certs.ErrReservationExpired):
		s.renderError(w, r, http.StatusGone, "This link was already used or has expired. Create a new one in AuthStep.")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeProfile(w, profile)
	}
}

func writeProfile(w http.ResponseWriter, profile []byte) {
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="authstep.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(profile)
}
