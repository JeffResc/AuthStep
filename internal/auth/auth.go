// Package auth implements OIDC sign-in, server-side sessions, CSRF
// protection and group-based authorization.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/config"
	"github.com/JeffResc/AuthStep/internal/store"
)

const (
	SessionIdle   = 8 * time.Hour
	SessionMax    = 24 * time.Hour
	touchInterval = time.Minute
	loginStateTTL = 10 * time.Minute
	sessionCookie = "__Host-authstep_session"
	loginCookie   = "__Host-authstep_login"
	CSRFHeader    = "X-CSRF-Token"
	CSRFFormField = "csrf_token"
)

// DeniedFunc renders an error page.
type DeniedFunc func(w http.ResponseWriter, r *http.Request, status int, msg string)

type Auth struct {
	store       *store.Store
	audit       *audit.Recorder
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
	issuerGroup string
	adminGroup  string
	// skipEmailVerified turns off the email_verified check in authorize.
	skipEmailVerified bool
	log               *slog.Logger
	now               func() time.Time

	// Denied renders sign-in failures and CSRF rejections.
	Denied DeniedFunc
}

// New discovers the OIDC provider and returns an Auth.
func New(ctx context.Context, cfg *config.Config, st *store.Store, rec *audit.Recorder, log *slog.Logger) (*Auth, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &Auth{
		store: st,
		audit: rec,
		oauth: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.BaseURL.JoinPath("/auth/callback").String(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile", "groups"},
		},
		verifier:          provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		groupsClaim:       cfg.GroupsClaim,
		issuerGroup:       cfg.IssuerGroup,
		adminGroup:        cfg.AdminGroup,
		skipEmailVerified: cfg.OIDCSkipEmailVerified,
		log:               log,
		now:               time.Now,
	}, nil
}

type loginState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Expires  time.Time `json:"e"`
	// Next is the local page to return to after sign-in.
	Next string `json:"r"`
}

// Login starts the authorization code flow. The optional next query
// parameter is the local page to return to afterwards.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !LocalPath(next) {
		next = "/"
	}
	ls := loginState{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		Expires:  a.now().Add(loginStateTTL),
		Next:     next,
	}
	b, _ := json.Marshal(ls)
	http.SetCookie(w, &http.Cookie{
		Name: loginCookie, Value: base64.RawURLEncoding.EncodeToString(b),
		Path: "/", MaxAge: int(loginStateTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, a.oauth.AuthCodeURL(ls.State, oidc.Nonce(ls.Nonce), oauth2.S256ChallengeOption(ls.Verifier)), http.StatusFound)
}

// Callback completes sign-in and creates a session.
func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	ls, err := a.readLoginState(w, r)
	if err != nil {
		a.log.Warn("login rejected", "reason", err)
		a.Denied(w, r, http.StatusBadRequest, "Your sign-in attempt expired or was invalid. Please try again.")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.log.Warn("login rejected by identity provider", "error", e, "description", q.Get("error_description"))
		a.Denied(w, r, http.StatusUnauthorized, "The identity provider did not complete sign-in.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(ls.State)) != 1 {
		a.log.Warn("login rejected", "reason", "state mismatch")
		a.Denied(w, r, http.StatusBadRequest, "Your sign-in attempt expired or was invalid. Please try again.")
		return
	}

	id, err := a.exchange(r.Context(), q.Get("code"), ls)
	if err != nil {
		a.log.Error("login failed", "err", err)
		a.Denied(w, r, http.StatusUnauthorized, "Sign-in failed. Please try again.")
		return
	}
	if err := a.authorize(id); err != nil {
		if err := a.audit.Record(r, audit.Actor{Sub: id.Sub, Email: id.Email}, audit.LoginDenied, id.Sub, map[string]any{"reason": err.Error()}); err != nil {
			a.fail(w, r, err)
			return
		}
		a.Denied(w, r, http.StatusForbidden, "Your account is not allowed to use AuthStep. Ask your administrator for access.")
		return
	}

	now := a.now()
	user := store.User{Sub: id.Sub, Email: id.Email, Name: id.Name, IsAdmin: slices.Contains(id.Groups, a.adminGroup), LastLoginAt: now}
	if err := a.store.UpsertUser(r.Context(), user); err != nil {
		a.fail(w, r, err)
		return
	}

	// Replace any existing session so a session ID is never reused across logins.
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := a.store.DeleteSession(r.Context(), hashToken(c.Value)); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	token := randomToken()
	if err := a.store.CreateSession(r.Context(), hashToken(token), user.Sub, randomToken(), now); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.audit.Record(r, audit.Actor{Sub: user.Sub, Email: user.Email}, audit.Login, user.Sub, map[string]any{"admin": user.IsAdmin}); err != nil {
		a.fail(w, r, err)
		return
	}
	setSessionCookie(w, token)
	next := ls.Next
	if !LocalPath(next) {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// LocalPath reports whether p is a path on this site, so redirecting to it
// cannot send the user elsewhere. Browsers treat "//host", backslashes and
// stripped tab or newline characters as ways to reach another host.
func LocalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\t\r\n") {
		return false
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// Logout deletes the session. It is a POST protected by CSRF.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := a.store.DeleteSession(r.Context(), hashToken(c.Value)); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Auth) readLoginState(w http.ResponseWriter, r *http.Request) (*loginState, error) {
	c, err := r.Cookie(loginCookie)
	if err != nil {
		return nil, errors.New("missing login state cookie")
	}
	clearCookie(w, loginCookie)
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, fmt.Errorf("decode login state: %w", err)
	}
	var ls loginState
	if err := json.Unmarshal(b, &ls); err != nil {
		return nil, fmt.Errorf("decode login state: %w", err)
	}
	if a.now().After(ls.Expires) {
		return nil, errors.New("login state expired")
	}
	return &ls, nil
}

type identity struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
}

func (a *Auth) exchange(ctx context.Context, code string, ls *loginState) (*identity, error) {
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(ls.Verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("token response has no id_token")
	}
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(ls.Nonce)) != 1 {
		return nil, errors.New("id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("id_token claims: %w", err)
	}
	id := &identity{Sub: idt.Subject}
	id.Email, _ = claims["email"].(string)
	id.EmailVerified, _ = claims["email_verified"].(bool)
	id.Name, _ = claims["name"].(string)
	if id.Name == "" {
		id.Name = id.Email
	}
	id.Groups = stringList(claims[a.groupsClaim])
	return id, nil
}

// authorize requires an email, verified unless skipEmailVerified is set, and
// membership of the issuer group.
func (a *Auth) authorize(id *identity) error {
	switch {
	case id.Email == "":
		return errors.New("no email claim")
	case !id.EmailVerified && !a.skipEmailVerified:
		return errors.New("email not verified")
	case !slices.Contains(id.Groups, a.issuerGroup):
		return fmt.Errorf("not in issuer group %q", a.issuerGroup)
	}
	return nil
}

// stringList accepts a JSON array of strings or a single string, since IdPs
// differ in how they encode a one-element groups claim.
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (a *Auth) fail(w http.ResponseWriter, r *http.Request, err error) {
	a.log.Error("internal error", "path", r.URL.Path, "err", err)
	a.Denied(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(SessionMax.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
