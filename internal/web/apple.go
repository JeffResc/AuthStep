package web

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/scep"
	"github.com/JeffResc/AuthStep/internal/store"
)

type appleView struct {
	ID         string
	DeviceName string
}

func (s *Server) appleForm(w http.ResponseWriter, r *http.Request, _ store.User) {
	s.render(w, http.StatusOK, "apple", newPageData(r, "Add Apple device"))
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
	d := newPageData(r, "Install profile")
	d.View = appleView{ID: c.ID, DeviceName: c.DeviceName}
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
