package scep

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/keypair"
	"github.com/JeffResc/AuthStep/internal/store"
)

type env struct {
	svc   *Service
	st    *store.Store
	certs *certs.Service
	user  store.User
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	certPath, keyPath := writePair(t, dir, "profile-signer.example.com")
	signer, err := keypair.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{st: st, clock: time.Now()}
	e.svc = New(st, audit.New(st, nil, nil, discard), signer, "https://ca.example.com/scep/authstep-scep", discard)
	e.svc.now = func() time.Time { return e.clock }
	e.certs = certs.New(st, nil, discard)
	e.user = store.User{Sub: "sub-alice", Email: "alice@example.com", Name: "Alice", LastLoginAt: e.clock}
	if err := st.UpsertUser(context.Background(), e.user); err != nil {
		t.Fatal(err)
	}
	return e
}

// writePair writes a self-signed certificate and key for cn.
func writePair(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, cn+".crt"), filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

type profileDoc struct {
	PayloadType    string `plist:"PayloadType"`
	PayloadContent []struct {
		PayloadType    string `plist:"PayloadType"`
		PayloadContent struct {
			URL            string            `plist:"URL"`
			Subject        [][][]string      `plist:"Subject"`
			SubjectAltName map[string]string `plist:"SubjectAltName"`
			Challenge      string            `plist:"Challenge"`
			KeyType        string            `plist:"Key Type"`
			Keysize        int               `plist:"Keysize"`
		} `plist:"PayloadContent"`
	} `plist:"PayloadContent"`
}

// enrol reserves an SCEP record and downloads its profile, returning the
// record ID and the challenge from the verified profile.
func (e *env) enrol(t *testing.T) (string, string) {
	t.Helper()
	ctx := context.Background()
	res, err := e.certs.Reserve(ctx, e.user, "iPhone", "scep")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := e.svc.Profile(ctx, e.user, res.ID)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("profile signature: %v", err)
	}
	if cn := p7.GetOnlySigner().Subject.CommonName; cn != "profile-signer.example.com" {
		t.Fatalf("signer = %q", cn)
	}
	var doc profileDoc
	if _, err := plist.Unmarshal(p7.Content, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.PayloadType != "Configuration" || len(doc.PayloadContent) != 1 || doc.PayloadContent[0].PayloadType != "com.apple.security.scep" {
		t.Fatalf("profile structure: %+v", doc)
	}
	c := doc.PayloadContent[0].PayloadContent
	switch {
	case c.URL != "https://ca.example.com/scep/authstep-scep":
		t.Fatalf("URL = %q", c.URL)
	case len(c.Subject) != 1 || c.Subject[0][0][0] != "CN" || c.Subject[0][0][1] != e.user.Email:
		t.Fatalf("Subject = %v", c.Subject)
	case c.SubjectAltName["rfc822Name"] != e.user.Email || c.SubjectAltName["uniformResourceIdentifier"] != certs.DeviceURI(res.ID):
		t.Fatalf("SubjectAltName = %v", c.SubjectAltName)
	case c.KeyType != "RSA" || c.Keysize != 2048:
		t.Fatalf("key = %s %d", c.KeyType, c.Keysize)
	case len(c.Challenge) < 40:
		t.Fatalf("challenge %q is too short", c.Challenge)
	}
	return res.ID, c.Challenge
}

func TestProfileIsOneTime(t *testing.T) {
	e := newEnv(t)
	id, _ := e.enrol(t)
	if _, err := e.svc.Profile(context.Background(), e.user, id); !errors.Is(err, store.ErrChallengeExists) {
		t.Fatalf("second download: err = %v, want ErrChallengeExists", err)
	}
}

func TestProfileRefusesOtherRecords(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	browser, err := e.certs.Reserve(ctx, e.user, "laptop", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Profile(ctx, e.user, browser.ID); !errors.Is(err, ErrNotSCEP) {
		t.Fatalf("browser record: err = %v, want ErrNotSCEP", err)
	}
	mine, err := e.certs.Reserve(ctx, e.user, "iPhone", "scep")
	if err != nil {
		t.Fatal(err)
	}
	mallory := store.User{Sub: "sub-mallory", Email: "mallory@example.com", LastLoginAt: e.clock}
	if err := e.st.UpsertUser(ctx, mallory); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Profile(ctx, mallory, mine.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other user: err = %v, want ErrNotFound", err)
	}
	e.clock = e.clock.Add(certs.PendingTTL + time.Second)
	if _, err := e.svc.Profile(ctx, e.user, mine.ID); !errors.Is(err, certs.ErrReservationExpired) {
		t.Fatalf("expired: err = %v, want ErrReservationExpired", err)
	}
}

func post(t *testing.T, h http.HandlerFunc, body any) (int, webhookResponse, map[string]string) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)))
	var resp struct {
		Allow bool              `json:"allow"`
		Data  map[string]string `json:"data"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, webhookResponse{Allow: resp.Allow}, resp.Data
}

func challengeReq(ch, tx string) map[string]any {
	return map[string]any{"scepChallenge": ch, "scepTransactionID": tx, "x509CertificateRequest": map[string]any{}}
}

func TestChallengeWebhook(t *testing.T) {
	e := newEnv(t)
	id, challenge := e.enrol(t)

	code, resp, data := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1"))
	if code != 200 || !resp.Allow || data["email"] != e.user.Email || data["deviceURI"] != certs.DeviceURI(id) {
		t.Fatalf("first use: %d %+v %v", code, resp, data)
	}
	if c, _ := e.st.CertificateByID(context.Background(), id); c.Status != "issuing" {
		t.Fatalf("status = %q, want issuing", c.Status)
	}

	// step-ca retries with the same transaction after a 5xx or a lost response.
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); !resp.Allow {
		t.Fatal("retry with the same transaction was denied")
	}
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-2")); resp.Allow {
		t.Fatal("reuse by another transaction was allowed")
	}
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq("not-a-challenge", "tx-3")); resp.Allow {
		t.Fatal("unknown challenge was allowed")
	}
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq("", "")); resp.Allow {
		t.Fatal("empty challenge was allowed")
	}
}

func TestChallengeExpires(t *testing.T) {
	e := newEnv(t)
	_, challenge := e.enrol(t)
	e.clock = e.clock.Add(ChallengeTTL)
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); resp.Allow {
		t.Fatal("expired challenge was allowed")
	}
}

func issuedCert(t *testing.T, email, uri string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: email},
		EmailAddresses: []string{email}, URIs: []*url.URL{u},
		NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNotifySuccess(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, challenge := e.enrol(t)
	post(t, e.svc.Challenge, challengeReq(challenge, "tx-1"))

	raw := issuedCert(t, e.user.Email, certs.DeviceURI(id))
	body := map[string]any{"scepTransactionID": "tx-1", "x509Certificate": map[string]any{"raw": raw}}
	for range 2 { // the second is a duplicate notification
		if code, _, _ := post(t, e.svc.Notify, body); code != http.StatusOK {
			t.Fatalf("notify: %d", code)
		}
	}
	c, err := e.st.CertificateByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "active" || c.Serial != "4242" {
		t.Fatalf("record = %s %q, want active 4242", c.Status, c.Serial)
	}
	entries, err := e.st.ListAuditEntries(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != audit.CertIssued || entries[0].ActorSub != e.user.Sub || entries[0].Details["serial"] != "4242" {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestNotifyFailure(t *testing.T) {
	e := newEnv(t)
	id, challenge := e.enrol(t)
	post(t, e.svc.Challenge, challengeReq(challenge, "tx-1"))
	post(t, e.svc.Notify, map[string]any{"scepTransactionID": "tx-1", "scepErrorCode": 2, "scepErrorDescription": "bad request"})
	if c, _ := e.st.CertificateByID(context.Background(), id); c.Status != "failed" {
		t.Fatalf("status = %q, want failed", c.Status)
	}
	if code, _, _ := post(t, e.svc.Notify, map[string]any{"scepTransactionID": "unknown"}); code != http.StatusOK {
		t.Fatalf("unknown transaction: %d, want 200", code)
	}
}

func TestRequireCA(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := RequireCA("step-ca.example.svc", ok)
	leaf := func(dns string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{DNSNames: []string{dns}}}}}
		return r
	}
	for _, tt := range []struct {
		name string
		req  *http.Request
		want int
	}{
		{"step-ca", leaf("step-ca.example.svc"), http.StatusOK},
		{"other name", leaf("attacker.example.svc"), http.StatusForbidden},
		{"no TLS", httptest.NewRequest(http.MethodPost, "/", nil), http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tt.req)
		if rec.Code != tt.want {
			t.Errorf("%s: %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
}
