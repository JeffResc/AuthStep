package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/store"
)

const auditPageSize = 200

// confirmView drives confirm.html, a page with one POST button.
type confirmView struct {
	Heading string
	Body    string
	Action  string
	Button  string
	Cancel  string
	Reasons []certs.Reason
}

// requireAdmin allows only signed-in admins. Admin status comes from the
// groups claim at the user's latest login.
func (s *Server) requireAdmin(h func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return s.requirePage(func(w http.ResponseWriter, r *http.Request, user store.User) {
		if !user.IsAdmin {
			s.renderError(w, r, http.StatusForbidden, "This page is for administrators.")
			return
		}
		h(w, r, user)
	})
}

func actor(u store.User) audit.Actor { return audit.Actor{Sub: u.Sub, Email: u.Email} }

// ---- Revoking one certificate ----

func (s *Server) confirmRevoke(w http.ResponseWriter, r *http.Request, user store.User) {
	c, ok := s.loadCert(w, r, user, false)
	if !ok {
		return
	}
	s.renderRevokeConfirm(w, r, c, "/certs/"+url.PathEscape(c.ID)+"/revoke", "/")
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, user store.User) {
	c, ok := s.loadCert(w, r, user, false)
	if !ok {
		return
	}
	if s.doRevoke(w, r, user, c) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) adminConfirmRevoke(w http.ResponseWriter, r *http.Request, user store.User) {
	c, ok := s.loadCert(w, r, user, true)
	if !ok {
		return
	}
	back := adminUserPath(c.UserSub)
	s.renderRevokeConfirm(w, r, c, "/admin/certs/"+url.PathEscape(c.ID)+"/revoke", back)
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request, user store.User) {
	c, ok := s.loadCert(w, r, user, true)
	if !ok {
		return
	}
	if s.doRevoke(w, r, user, c) {
		http.Redirect(w, r, adminUserPath(c.UserSub), http.StatusSeeOther)
	}
}

// loadCert loads the {id} certificate. Without anyOwner, it must belong to user.
func (s *Server) loadCert(w http.ResponseWriter, r *http.Request, user store.User, anyOwner bool) (*store.Certificate, bool) {
	var (
		c   *store.Certificate
		err error
	)
	if anyOwner {
		c, err = s.store.CertificateByID(r.Context(), r.PathValue("id"))
	} else {
		c, err = s.store.UserCertificate(r.Context(), user.Sub, r.PathValue("id"))
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "Certificate not found.")
		return nil, false
	case err != nil:
		s.fail(w, r, err)
		return nil, false
	case c.Status != "active":
		s.renderError(w, r, http.StatusConflict, "This certificate is not active.")
		return nil, false
	}
	return c, true
}

func (s *Server) renderRevokeConfirm(w http.ResponseWriter, r *http.Request, c *store.Certificate, action, cancel string) {
	d := newPageData(r, "Revoke certificate")
	d.View = confirmView{
		Heading: "Revoke certificate",
		Body: fmt.Sprintf("Revoke the certificate for %q? Services that check revocation will stop accepting it. This cannot be undone.",
			c.DeviceName),
		Action:  action,
		Button:  "Revoke",
		Cancel:  cancel,
		Reasons: certs.UserReasons,
	}
	s.render(w, http.StatusOK, "confirm", d)
}

// doRevoke revokes c and records it. It reports whether it succeeded; on
// failure it has written the response.
func (s *Server) doRevoke(w http.ResponseWriter, r *http.Request, user store.User, c *store.Certificate) bool {
	reason, ok := certs.ReasonByName(r.PostFormValue("reason"))
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Choose a reason.")
		return false
	}
	if err := s.certs.Revoke(r.Context(), c, user.Sub, reason); err != nil {
		s.revokeFailed(w, r, err)
		return false
	}
	if err := s.recordRevoke(r, user, *c, reason); err != nil {
		s.fail(w, r, err)
		return false
	}
	return true
}

func (s *Server) recordRevoke(r *http.Request, user store.User, c store.Certificate, reason certs.Reason) error {
	return s.audit.Record(r, actor(user), audit.CertRevoked, c.ID, map[string]any{
		"serial": c.Serial, "owner": c.UserSub, "device": c.DeviceName, "reason": reason.Name,
	})
}

func (s *Server) revokeFailed(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotActive) {
		s.renderError(w, r, http.StatusConflict, "This certificate is not active.")
		return
	}
	s.log.Error("revoke failed", "err", err)
	s.renderError(w, r, http.StatusBadGateway, "The certificate authority did not confirm the revocation. Try again.")
}

// ---- Users and limits ----

type adminUsersView struct {
	DefaultLimit int
	Users        []store.UserSummary
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request, _ store.User) {
	limit, err := s.store.DefaultCertLimit(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	users, err := s.store.ListUsers(r.Context(), time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := newPageData(r, "Users")
	d.View = adminUsersView{DefaultLimit: limit, Users: users}
	s.render(w, http.StatusOK, "admin_users", d)
}

func (s *Server) adminSetDefaultLimit(w http.ResponseWriter, r *http.Request, user store.User) {
	limit, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("limit")))
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "The limit must be a whole number.")
		return
	}
	if err := s.store.SetDefaultCertLimit(r.Context(), limit); err != nil {
		s.limitFailed(w, r, err)
		return
	}
	if err := s.audit.Record(r, actor(user), audit.DefaultLimitSet, "default", map[string]any{"limit": limit}); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

type adminUserView struct {
	Summary      store.UserSummary
	DefaultLimit int
	Certificates []certView
	HasActive    bool
}

func (s *Server) adminUser(w http.ResponseWriter, r *http.Request, _ store.User) {
	sub := r.PathValue("sub")
	sum, ok := s.loadUser(w, r, sub)
	if !ok {
		return
	}
	limit, err := s.store.DefaultCertLimit(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.store.ListUserCertificates(r.Context(), sub)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := adminUserView{Summary: *sum, DefaultLimit: limit}
	now := time.Now()
	for _, c := range list {
		if c.Status == "pending" {
			continue
		}
		cv := newCertView(c, now)
		v.HasActive = v.HasActive || c.Status == "active"
		v.Certificates = append(v.Certificates, cv)
	}
	d := newPageData(r, sum.Email)
	d.View = v
	s.render(w, http.StatusOK, "admin_user", d)
}

func (s *Server) adminSetUserLimit(w http.ResponseWriter, r *http.Request, user store.User) {
	sub := r.PathValue("sub")
	var limit *int
	if v := strings.TrimSpace(r.PostFormValue("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			s.renderError(w, r, http.StatusBadRequest, "The limit must be a whole number, or empty to use the default.")
			return
		}
		limit = &n
	}
	if err := s.store.SetUserCertLimit(r.Context(), sub, limit); err != nil {
		s.limitFailed(w, r, err)
		return
	}
	var logged any // null in the audit log means "use the default"
	if limit != nil {
		logged = *limit
	}
	if err := s.audit.Record(r, actor(user), audit.UserLimitSet, sub, map[string]any{"limit": logged}); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, adminUserPath(sub), http.StatusSeeOther)
}

func (s *Server) limitFailed(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidLimit):
		s.renderError(w, r, http.StatusBadRequest, "The limit must be between 0 and 1000.")
	case errors.Is(err, store.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "User not found.")
	default:
		s.fail(w, r, err)
	}
}

func (s *Server) adminConfirmRevokeAll(w http.ResponseWriter, r *http.Request, _ store.User) {
	sum, ok := s.loadUser(w, r, r.PathValue("sub"))
	if !ok {
		return
	}
	d := newPageData(r, "Revoke all certificates")
	d.View = confirmView{
		Heading: "Revoke all certificates",
		Body: fmt.Sprintf("Revoke all %d active certificates of %s? Use this when someone leaves. They can still sign in if the identity provider allows it.",
			sum.ActiveCerts, sum.Email),
		Action: adminUserPath(sum.Sub) + "/revoke-all",
		Button: "Revoke all",
		Cancel: adminUserPath(sum.Sub),
	}
	s.render(w, http.StatusOK, "confirm", d)
}

func (s *Server) adminRevokeAll(w http.ResponseWriter, r *http.Request, user store.User) {
	sub := r.PathValue("sub")
	if _, ok := s.loadUser(w, r, sub); !ok {
		return
	}
	done, revokeErr := s.certs.RevokeAll(r.Context(), sub, user.Sub)
	// Record what was revoked even when a later certificate failed.
	for _, c := range done {
		if err := s.recordRevoke(r, user, c, certs.ReasonOffboarded); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if revokeErr != nil {
		s.revokeFailed(w, r, revokeErr)
		return
	}
	http.Redirect(w, r, adminUserPath(sub), http.StatusSeeOther)
}

func (s *Server) loadUser(w http.ResponseWriter, r *http.Request, sub string) (*store.UserSummary, bool) {
	sum, err := s.store.UserSummary(r.Context(), sub, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.renderError(w, r, http.StatusNotFound, "User not found.")
		return nil, false
	}
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	return sum, true
}

func adminUserPath(sub string) string { return "/admin/users/" + url.PathEscape(sub) }

// ---- Audit log ----

type auditRow struct {
	Time    string
	Actor   string
	Action  string
	Target  string
	IP      string
	Details string
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request, _ store.User) {
	entries, err := s.store.ListAuditEntries(r.Context(), auditPageSize)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		details, err := json.Marshal(e.Details)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		rows = append(rows, auditRow{
			Time: e.Time.UTC().Format("2006-01-02 15:04:05Z"), Actor: e.ActorEmail, Action: e.Action,
			Target: e.Target, IP: e.IP, Details: string(details),
		})
	}
	d := newPageData(r, "Audit log")
	d.View = rows
	s.render(w, http.StatusOK, "admin_audit", d)
}
