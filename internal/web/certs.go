package web

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/auth"
	"github.com/JeffResc/AuthStep/internal/ca"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/store"
)

const maxAPIBody = 64 << 10

type certView struct {
	ID         string
	DeviceName string
	Status     string
	// StatusClass styles the status badge.
	StatusClass string
	// Note explains what happens next for an Apple device being enrolled.
	Note    string
	Expires string
	Serial  string
	// ContinueURL resumes an Apple enrolment whose profile was not downloaded yet.
	ContinueURL string
	Revocable   bool
}

func newCertView(c store.Certificate, now time.Time) certView {
	v := certView{ID: c.ID, DeviceName: c.DeviceName, Serial: c.Serial, Revocable: c.Status == "active" && !c.Expired(now)}
	switch {
	case c.Expired(now):
		v.Status, v.StatusClass = "Expired", "expired"
	case c.Status == "active":
		v.Status, v.StatusClass = "Active", "active"
	case c.Status == "revoked":
		v.Status, v.StatusClass = "Revoked", "revoked"
	case c.Status == "issuing":
		v.Status, v.StatusClass = "Issuing", "waiting"
		v.Note = "The device is requesting its certificate."
	case c.Status == "failed":
		v.Status, v.StatusClass = "Failed", "failed"
	case c.Status == "pending":
		v.Status, v.StatusClass = "Waiting for download", "waiting"
		v.Note = "Download the profile on the device."
		v.ContinueURL = "/certs/" + url.PathEscape(c.ID) + "/apple"
	}
	if !c.NotAfter.IsZero() {
		v.Expires = c.NotAfter.UTC().Format("2 Jan 2006")
	}
	return v
}

// requirePage sends signed-out users to sign in, then back to this page.
func (s *Server) requirePage(h func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFrom(r.Context())
		if sess == nil {
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		h(w, r, sess.User)
	}
}

// requireAPI answers 401 for signed-out users. CSRF is enforced by the
// auth.CSRF middleware for every signed-in POST.
func (s *Server) requireAPI(h func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFrom(r.Context())
		if sess == nil {
			writeJSONError(w, http.StatusUnauthorized, "Your session ended. Sign in again.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAPIBody)
		h(w, r, sess.User)
	}
}

func (s *Server) newCert(w http.ResponseWriter, r *http.Request, _ store.User) {
	s.render(w, http.StatusOK, "newcert", newPageData(r, "New certificate"))
}

func (s *Server) reserveCert(w http.ResponseWriter, r *http.Request, user store.User) {
	var req struct {
		DeviceName string `json:"deviceName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Bad request.")
		return
	}
	res, err := s.certs.Reserve(r.Context(), user, req.DeviceName, "browser")
	switch {
	case errors.Is(err, certs.ErrInvalidDeviceName):
		writeJSONError(w, http.StatusBadRequest, "Device name must be 1 to 64 printable characters.")
	case errors.Is(err, store.ErrLimitReached):
		writeJSONError(w, http.StatusConflict, "You have reached your certificate limit. Revoke a certificate you no longer use, or ask an administrator to raise your limit.")
	case err != nil:
		s.apiFail(w, r, err)
	default:
		writeJSON(w, http.StatusCreated, res)
	}
}

func (s *Server) issueCert(w http.ResponseWriter, r *http.Request, user store.User) {
	var req struct {
		CSR string `json:"csr"` // base64 DER
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Bad request.")
		return
	}
	der, err := base64.StdEncoding.DecodeString(req.CSR)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Bad request.")
		return
	}

	signed, err := s.certs.Issue(r.Context(), user, r.PathValue("id"), der)
	var caErr *ca.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "Certificate request not found.")
	case errors.Is(err, store.ErrNotPending), errors.Is(err, certs.ErrReservationExpired):
		writeJSONError(w, http.StatusConflict, "This request expired or was already used. Start again.")
	case errors.Is(err, certs.ErrInvalidCSR):
		s.log.Warn("csr rejected", "sub", user.Sub, "err", err)
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errors.As(err, &caErr):
		s.log.Error("step-ca refused to sign", "sub", user.Sub, "status", caErr.Status, "message", caErr.Message)
		writeJSONError(w, http.StatusBadGateway, "The certificate authority refused the request. Try again later.")
	case err != nil:
		s.apiFail(w, r, err)
	default:
		if err := s.audit.Record(r, actor(user), audit.CertIssued, r.PathValue("id"), map[string]any{
			"serial": signed.Leaf.SerialNumber.String(), "not_after": signed.Leaf.NotAfter.UTC(),
		}); err != nil {
			s.apiFail(w, r, err)
			return
		}
		chain := make([]string, 0, len(signed.Chain))
		for _, c := range signed.Chain {
			chain = append(chain, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed.Leaf.Raw})),
			"chain":       chain,
		})
	}
}

func (s *Server) apiFail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", r.URL.Path, "err", err)
	writeJSONError(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
