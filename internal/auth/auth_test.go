package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/config"
	"github.com/JeffResc/AuthStep/internal/store"
)

// fakeIdP is a minimal OIDC provider. It enforces PKCE (S256) at the token
// endpoint and issues ID tokens with the claims set in Claims.
type fakeIdP struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu            sync.Mutex
	Claims        map[string]any
	StateOverride string
	NonceOverride string
	codes         map[string]authReq
}

type authReq struct{ nonce, challenge string }

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, codes: map[string]authReq{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /keys", f.keys)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIdP) discovery(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.URL,
		"authorization_endpoint":                f.URL + "/authorize",
		"token_endpoint":                        f.URL + "/token",
		"jwks_uri":                              f.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeIdP) keys(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
}

func (f *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	code := randomToken()
	f.mu.Lock()
	f.codes[code] = authReq{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	state := q.Get("state")
	if f.StateOverride != "" {
		state = f.StateOverride
	}
	f.mu.Unlock()
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), http.StatusFound)
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	req, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != req.challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}

	nonce := req.nonce
	if f.NonceOverride != "" {
		nonce = f.NonceOverride
	}
	claims := map[string]any{
		"iss": f.URL, "aud": "authstep", "sub": "user-1", "nonce": nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for k, v := range f.Claims {
		claims[k] = v
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		panic(err)
	}
	idt, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idt})
}

type env struct {
	idp    *fakeIdP
	app    *httptest.Server
	client *http.Client
	auth   *Auth
	store  *store.Store

	clockMu sync.Mutex
	clock   time.Time
}

// advance moves the clock AuthStep sees. The server reads it from its own
// goroutines, so it is guarded by a mutex.
func (e *env) advance(d time.Duration) {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	e.clock = e.clock.Add(d)
}

func newEnv(t *testing.T, claims map[string]any) *env {
	t.Helper()
	return newEnvWith(t, claims, func(*config.Config) {})
}

func newEnvWith(t *testing.T, claims map[string]any, mod func(*config.Config)) *env {
	t.Helper()
	e := &env{idp: newFakeIdP(t), clock: time.Now()}
	e.idp.Claims = claims

	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})

	e.app = httptest.NewUnstartedServer(nil)
	e.app.StartTLS()
	t.Cleanup(e.app.Close)
	base, _ := url.Parse(e.app.URL)

	cfg := &config.Config{
		BaseURL: base, OIDCIssuer: e.idp.URL, OIDCClientID: "authstep", OIDCClientSecret: "secret",
		GroupsClaim: "groups", IssuerGroup: "authstep-users", AdminGroup: "authstep-admins",
	}
	mod(cfg)
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(context.Background(), cfg, st, audit.New(st, nil, nil, discard), discard)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time {
		e.clockMu.Lock()
		defer e.clockMu.Unlock()
		return e.clock
	}
	a.Denied = func(w http.ResponseWriter, r *http.Request, status int, msg string) { http.Error(w, msg, status) }
	e.auth = a
	e.store = st

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s := SessionFrom(r.Context())
		if s == nil {
			_, _ = fmt.Fprint(w, "anonymous")
			return
		}
		_, _ = fmt.Fprintf(w, "user=%s admin=%v csrf=%s", s.User.Email, s.User.IsAdmin, s.CSRFToken)
	})
	mux.HandleFunc("GET /auth/login", a.Login)
	mux.HandleFunc("GET /auth/callback", a.Callback)
	mux.HandleFunc("POST /auth/logout", a.Logout)
	e.app.Config.Handler = a.Session(a.CSRF(mux))

	e.client = e.app.Client()
	e.client.Jar, _ = cookiejar.New(nil)
	return e
}

func (e *env) do(t *testing.T, method, path string, form url.Values) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.app.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func (e *env) login(t *testing.T) (int, string) {
	t.Helper()
	return e.do(t, http.MethodGet, "/auth/login", nil)
}

func (e *env) sessionCookie(t *testing.T) string {
	t.Helper()
	u, _ := url.Parse(e.app.URL)
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	return ""
}

func member(groups ...any) map[string]any {
	return map[string]any{"email": "alice@example.com", "email_verified": true, "name": "Alice", "groups": groups}
}

func TestLoginAllowed(t *testing.T) {
	tests := []struct {
		name      string
		claims    map[string]any
		wantAdmin bool
	}{
		{"issuer group", member("authstep-users"), false},
		{"issuer and admin group", member("authstep-users", "authstep-admins"), true},
		{"groups claim as a string", map[string]any{"email": "alice@example.com", "email_verified": true, "groups": "authstep-users"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.claims)
			code, body := e.login(t)
			want := fmt.Sprintf("user=alice@example.com admin=%v", tt.wantAdmin)
			if code != http.StatusOK || !strings.HasPrefix(body, want) {
				t.Fatalf("got %d %q, want 200 %q", code, body, want)
			}
			e.wantAudit(t, audit.Login)
		})
	}
}

func TestLoginDenied(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"not in issuer group", member("other")},
		{"admin group only", member("authstep-admins")},
		{"no groups", map[string]any{"email": "alice@example.com", "email_verified": true}},
		{"email not verified", map[string]any{"email": "alice@example.com", "email_verified": false, "groups": []any{"authstep-users"}}},
		{"no email", map[string]any{"email_verified": true, "groups": []any{"authstep-users"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.claims)
			if code, body := e.login(t); code != http.StatusForbidden {
				t.Fatalf("login: got %d %q, want 403", code, body)
			}
			if _, body := e.do(t, http.MethodGet, "/", nil); body != "anonymous" {
				t.Fatalf("after denied login: %q, want anonymous", body)
			}
			e.wantAudit(t, audit.LoginDenied)
		})
	}
}

func TestLoginSkipEmailVerified(t *testing.T) {
	skip := func(c *config.Config) { c.OIDCSkipEmailVerified = true }
	unverified := map[string]any{"email": "alice@example.com", "email_verified": false, "groups": []any{"authstep-users"}}
	e := newEnvWith(t, unverified, skip)
	if code, body := e.login(t); code != http.StatusOK || !strings.HasPrefix(body, "user=alice@example.com") {
		t.Fatalf("unverified email: got %d %q, want 200", code, body)
	}

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"no email", map[string]any{"groups": []any{"authstep-users"}}},
		{"not in issuer group", map[string]any{"email": "alice@example.com", "groups": []any{"other"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnvWith(t, tt.claims, skip)
			if code, body := e.login(t); code != http.StatusForbidden {
				t.Fatalf("login: got %d %q, want 403", code, body)
			}
			e.wantAudit(t, audit.LoginDenied)
		})
	}
}

func TestLoginRejectsStateMismatch(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	e.idp.StateOverride = "forged"
	if code, _ := e.login(t); code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", code)
	}
}

func TestLoginRejectsNonceMismatch(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	e.idp.NonceOverride = "forged"
	if code, _ := e.login(t); code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", code)
	}
}

func TestLoginRejectsExpiredLoginState(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	// Start the flow, then let the login state expire before the callback.
	e.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == "/auth/callback" {
			e.advance(loginStateTTL + time.Second)
		}
		return nil
	}
	if code, _ := e.login(t); code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", code)
	}
}

func TestLoginRotatesSession(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	e.login(t)
	first := e.sessionCookie(t)
	e.login(t)
	if second := e.sessionCookie(t); second == "" || second == first {
		t.Fatalf("session cookie not rotated")
	}

	req, _ := http.NewRequest(http.MethodGet, e.app.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: first})
	resp, err := e.app.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(b) != "anonymous" {
		t.Fatalf("old session still valid: %q", b)
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	_, body := e.login(t)
	csrf := body[strings.Index(body, "csrf=")+len("csrf="):]

	if code, _ := e.do(t, http.MethodPost, "/auth/logout", url.Values{}); code != http.StatusForbidden {
		t.Fatalf("logout without token: got %d, want 403", code)
	}
	if code, _ := e.do(t, http.MethodPost, "/auth/logout", url.Values{CSRFFormField: {"wrong"}}); code != http.StatusForbidden {
		t.Fatalf("logout with wrong token: got %d, want 403", code)
	}
	if _, body := e.do(t, http.MethodGet, "/", nil); !strings.HasPrefix(body, "user=") {
		t.Fatalf("rejected logout ended the session: %q", body)
	}

	if code, body := e.do(t, http.MethodPost, "/auth/logout", url.Values{CSRFFormField: {csrf}}); code != http.StatusOK || body != "anonymous" {
		t.Fatalf("logout: got %d %q, want 200 anonymous", code, body)
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	e.login(t)
	e.advance(SessionIdle + time.Minute)
	if _, body := e.do(t, http.MethodGet, "/", nil); body != "anonymous" {
		t.Fatalf("idle session still valid: %q", body)
	}
}

func TestSessionAbsoluteTimeout(t *testing.T) {
	e := newEnv(t, member("authstep-users"))
	e.login(t)
	// Stay active so the idle timeout never fires.
	for range 3 {
		e.advance(7 * time.Hour)
		if _, body := e.do(t, http.MethodGet, "/", nil); !strings.HasPrefix(body, "user=") {
			t.Fatalf("active session ended early: %q", body)
		}
	}
	e.advance(4 * time.Hour)
	if _, body := e.do(t, http.MethodGet, "/", nil); body != "anonymous" {
		t.Fatalf("session older than %v still valid: %q", SessionMax, body)
	}
}

func (e *env) wantAudit(t *testing.T, action string) {
	t.Helper()
	entries, err := e.store.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != action || entries[0].ActorSub != "user-1" || entries[0].IP != "127.0.0.1" {
		t.Fatalf("audit entries = %+v, want one %q by user-1 from 127.0.0.1", entries, action)
	}
}

func TestLocalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/":                     true,
		"/certs/apple":          true,
		"/certs/apple?here=1":   true,
		"":                      false,
		"certs/apple":           false,
		"//evil.example/x":      false,
		"/\\evil.example":       false,
		"/\t/evil.example":      false,
		"/\n/evil.example":      false,
		"https://evil.example/": false,
		"javascript:alert(1)":   false,
	} {
		if got := LocalPath(p); got != want {
			t.Errorf("LocalPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestLoginReturnsToNext(t *testing.T) {
	for next, wantPath := range map[string]string{
		"/certs/apple?here=1":  "/certs/apple",
		"//evil.example/":      "/",
		"https://evil.example": "/",
	} {
		e := newEnv(t, member("authstep-users"))
		resp, err := e.client.Get(e.app.URL + "/auth/login?next=" + url.QueryEscape(next))
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		final := resp.Request.URL
		if final.Host != strings.TrimPrefix(e.app.URL, "https://") || final.Path != wantPath {
			t.Errorf("next=%q: ended at %s, want %s on the app", next, final, wantPath)
		}
	}
}
