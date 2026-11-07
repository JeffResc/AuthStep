// Package web serves AuthStep's HTML UI.
package web

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/auth"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/scep"
	"github.com/JeffResc/AuthStep/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// expiryBanner is how long before expiry the home page warns about a certificate.
const expiryBanner = 30 * 24 * time.Hour

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

type Server struct {
	auth  *auth.Auth
	certs *certs.Service
	scep  *scep.Service
	store *store.Store
	audit *audit.Recorder
	log   *slog.Logger
	pages map[string]*template.Template
	hsts  bool
	// baseURL is the public URL without a trailing slash.
	baseURL string
}

// New returns the HTTP handler for the public listener. baseURL is the
// public URL; https base URLs also get a Strict-Transport-Security header.
func New(a *auth.Auth, c *certs.Service, sc *scep.Service, st *store.Store, rec *audit.Recorder, log *slog.Logger, baseURL *url.URL) (http.Handler, error) {
	s := &Server{auth: a, certs: c, scep: sc, store: st, audit: rec, log: log, pages: map[string]*template.Template{},
		hsts: baseURL.Scheme == "https", baseURL: strings.TrimSuffix(baseURL.String(), "/")}
	funcs := template.FuncMap{"pathEscape": url.PathEscape}
	for _, p := range []string{"login", "home", "newcert", "apple", "install", "handoff", "confirm", "admin_users", "admin_user", "admin_audit", "error"} {
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/guides.html", "templates/"+p+".html")
		if err != nil {
			return nil, err
		}
		s.pages[p] = t
	}
	a.Denied = s.renderError

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /auth/login", a.Login)
	mux.HandleFunc("GET /auth/callback", a.Callback)
	mux.HandleFunc("POST /auth/logout", a.Logout)
	mux.HandleFunc("GET /help/install", s.installHelp)
	mux.HandleFunc("GET /devices/add", s.requirePage(s.handoff))
	mux.HandleFunc("GET /certs/new", s.requirePage(s.newCert))
	mux.HandleFunc("POST /api/certs", s.requireAPI(s.reserveCert))
	mux.HandleFunc("POST /api/certs/{id}/csr", s.requireAPI(s.issueCert))
	mux.HandleFunc("GET /certs/apple", s.requirePage(s.appleForm))
	mux.HandleFunc("POST /certs/apple", s.requirePage(s.appleReserve))
	mux.HandleFunc("GET /certs/{id}/apple", s.requirePage(s.appleReady))
	mux.HandleFunc("GET /certs/{id}/apple.mobileconfig", s.requirePage(s.appleProfile))
	mux.HandleFunc("POST /certs/{id}/tv", s.requirePage(s.appleTVLink))
	mux.HandleFunc("GET /tv/{code}", s.tvProfile)
	mux.HandleFunc("POST /certs/{id}/cancel", s.requirePage(s.appleCancel))
	mux.HandleFunc("GET /certs/{id}/revoke", s.requirePage(s.confirmRevoke))
	mux.HandleFunc("POST /certs/{id}/revoke", s.requirePage(s.revoke))

	mux.HandleFunc("GET /admin/users", s.requireAdmin(s.adminUsers))
	mux.HandleFunc("POST /admin/limit", s.requireAdmin(s.adminSetDefaultLimit))
	mux.HandleFunc("GET /admin/users/{sub}", s.requireAdmin(s.adminUser))
	mux.HandleFunc("POST /admin/users/{sub}/limit", s.requireAdmin(s.adminSetUserLimit))
	mux.HandleFunc("GET /admin/users/{sub}/revoke-all", s.requireAdmin(s.adminConfirmRevokeAll))
	mux.HandleFunc("POST /admin/users/{sub}/revoke-all", s.requireAdmin(s.adminRevokeAll))
	mux.HandleFunc("GET /admin/certs/{id}/revoke", s.requireAdmin(s.adminConfirmRevoke))
	mux.HandleFunc("POST /admin/certs/{id}/revoke", s.requireAdmin(s.adminRevoke))
	mux.HandleFunc("GET /admin/audit", s.requireAdmin(s.adminAudit))

	return s.securityHeaders(a.Session(a.CSRF(mux))), nil
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if s.hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		next.ServeHTTP(w, r)
	})
}

type pageData struct {
	Title        string
	User         *store.User
	CSRF         string
	Message      string
	Certificates []certView
	// OS is the visitor's platform, for opening the matching install guide.
	OS string
	// DeviceExample is the example name in device name fields.
	DeviceExample string
	// View holds page-specific data.
	View any
}

func newPageData(r *http.Request, title string) pageData {
	d := pageData{Title: title, OS: detectOS(r.UserAgent()), DeviceExample: deviceExample(r.UserAgent())}
	if sess := auth.SessionFrom(r.Context()); sess != nil {
		d.User = &sess.User
		d.CSRF = sess.CSRFToken
	}
	return d
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	d := newPageData(r, "AuthStep")
	if d.User == nil {
		s.render(w, http.StatusOK, "login", d)
		return
	}
	list, err := s.certs.List(r.Context(), *d.User)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now()
	var expiring []certView
	for _, c := range list {
		v := newCertView(c, now)
		if c.Status == "pending" {
			expires, downloaded, err := s.store.SCEPChallengeExpiry(r.Context(), c.ID)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if downloaded {
				if !now.Before(expires) {
					continue // the profile can no longer enrol
				}
				v.Status, v.ContinueURL = "Waiting for device", ""
				v.Note = "Install the downloaded profile on the device within " + minutesLeft(expires.Sub(now)) + "."
			} else {
				linkExpires, linked, err := s.store.DeviceLinkExpiry(r.Context(), c.ID)
				if err != nil {
					s.fail(w, r, err)
					return
				}
				if linked {
					if !now.Before(linkExpires) {
						continue // the link can no longer be used
					}
					v.Status, v.ContinueURL = "Waiting for Apple TV", ""
					v.Note = "Type the link on the Apple TV within " + minutesLeft(linkExpires.Sub(now)) + "."
				}
			}
		}
		d.Certificates = append(d.Certificates, v)
		if v.Revocable && c.NotAfter.Sub(now) <= expiryBanner {
			expiring = append(expiring, v)
		}
	}
	d.View = expiring
	s.render(w, http.StatusOK, "home", d)
}

// minutesLeft renders a duration as whole minutes, rounded up.
func minutesLeft(d time.Duration) string {
	m := int((d + time.Minute - 1) / time.Minute)
	if m == 1 {
		return "1 minute"
	}
	return strconv.Itoa(m) + " minutes"
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", r.URL.Path, "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	d := newPageData(r, http.StatusText(status))
	d.Message = msg
	s.render(w, status, "error", d)
}

func (s *Server) render(w http.ResponseWriter, status int, page string, d pageData) {
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, "layout", d); err != nil {
		s.log.Error("render template", "page", page, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// A failed write means the client went away; there is nothing to do.
	_, _ = buf.WriteTo(w)
}
