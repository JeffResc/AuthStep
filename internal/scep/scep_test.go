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
	e.clock = e.clock.Add(certs.ChallengeTTL)
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

func TestCancelBeforeDownload(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	res, err := e.certs.Reserve(ctx, e.user, "iPhone", "scep")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CancelSCEPEnrolment(ctx, e.user.Sub, res.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CertificateByID(ctx, res.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record after cancel: err = %v, want ErrNotFound", err)
	}
	if _, err := e.svc.Profile(ctx, e.user, res.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("profile after cancel: err = %v, want ErrNotFound", err)
	}
}

func TestCancelledProfileCannotEnrol(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, challenge := e.enrol(t)
	if _, err := e.st.CancelSCEPEnrolment(ctx, e.user.Sub, id); err != nil {
		t.Fatal(err)
	}
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); resp.Allow {
		t.Fatal("a cancelled profile's challenge was allowed")
	}
	if _, err := e.st.CancelSCEPEnrolment(ctx, e.user.Sub, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second cancel: err = %v, want ErrNotFound", err)
	}
}

func TestCancelAfterEnrolmentStartedIsRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, challenge := e.enrol(t)
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); !resp.Allow {
		t.Fatal("challenge denied")
	}
	if _, err := e.st.CancelSCEPEnrolment(ctx, e.user.Sub, id); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("cancel while issuing: err = %v, want ErrNotPending", err)
	}
	if c, _ := e.st.CertificateByID(ctx, id); c.Status != "issuing" {
		t.Fatalf("status = %q, want issuing (untouched)", c.Status)
	}
}

func TestCancelOnlyOwnPendingAppleRequests(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	mine, err := e.certs.Reserve(ctx, e.user, "iPhone", "scep")
	if err != nil {
		t.Fatal(err)
	}
	browser, err := e.certs.Reserve(ctx, e.user, "laptop", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CancelSCEPEnrolment(ctx, "sub-mallory", mine.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other user: err = %v, want ErrNotFound", err)
	}
	if _, err := e.st.CancelSCEPEnrolment(ctx, e.user.Sub, browser.ID); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("browser reservation: err = %v, want ErrNotPending", err)
	}
}

// linkChallenge returns the challenge in a profile served by a device link.
func linkChallenge(t *testing.T, signed []byte, email string) string {
	t.Helper()
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("profile signature: %v", err)
	}
	var doc profileDoc
	if _, err := plist.Unmarshal(p7.Content, &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.PayloadContent[0].PayloadContent
	if c.SubjectAltName["rfc822Name"] != email {
		t.Fatalf("SubjectAltName = %v", c.SubjectAltName)
	}
	return c.Challenge
}

func TestDeviceLinkServesProfileOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	res, err := e.certs.Reserve(ctx, e.user, "Living Room Apple TV", "scep")
	if err != nil {
		t.Fatal(err)
	}
	code, expires, err := e.svc.CreateLink(ctx, e.user, res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 9 || code[4] != '-' || !expires.Equal(e.clock.Add(LinkTTL)) {
		t.Fatalf("code %q expires %v", code, expires)
	}
	if exp, ok, _ := e.st.DeviceLinkExpiry(ctx, res.ID); !ok || exp.Unix() != expires.Unix() {
		t.Fatalf("DeviceLinkExpiry = %v %v", exp, ok)
	}
	// Typed in lower case, without the hyphen.
	signed, err := e.svc.ProfileByLink(ctx, strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if err != nil {
		t.Fatal(err)
	}
	challenge := linkChallenge(t, signed, e.user.Email)
	if _, ok, _ := e.st.DeviceLinkExpiry(ctx, res.ID); ok {
		t.Fatal("link still listed as unused")
	}
	if _, err := e.svc.ProfileByLink(ctx, code); !errors.Is(err, store.ErrLinkUsed) {
		t.Fatalf("second use: err = %v, want ErrLinkUsed", err)
	}
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); !resp.Allow {
		t.Fatal("challenge from the linked profile was denied")
	}
}

func TestDeviceLinkRules(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	res, err := e.certs.Reserve(ctx, e.user, "Apple TV", "scep")
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := e.svc.CreateLink(ctx, e.user, res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateLink(ctx, e.user, res.ID); !errors.Is(err, store.ErrLinkExists) {
		t.Fatalf("second link: err = %v, want ErrLinkExists", err)
	}
	for _, bad := range []string{"", "ABCD-EFG", "ABCD-EFGHJ", "ABCD-EFG!", "UUUU-UUUU"} {
		if _, err := e.svc.ProfileByLink(ctx, bad); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("code %q: err = %v, want ErrNotFound", bad, err)
		}
	}
	e.clock = e.clock.Add(LinkTTL)
	if _, err := e.svc.ProfileByLink(ctx, code); !errors.Is(err, store.ErrLinkExpired) {
		t.Fatalf("expired: err = %v, want ErrLinkExpired", err)
	}

	// A link is not offered once the profile was downloaded directly.
	id, _ := e.enrol(t)
	if _, _, err := e.svc.CreateLink(ctx, e.user, id); !errors.Is(err, store.ErrChallengeExists) {
		t.Fatalf("after download: err = %v, want ErrChallengeExists", err)
	}

	// The link never outlives the reservation.
	late, err := e.certs.Reserve(ctx, e.user, "Bedroom Apple TV", "scep")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := e.st.CertificateByID(ctx, late.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.clock = rec.CreatedAt.Add(certs.PendingTTL - time.Minute)
	if _, exp, err := e.svc.CreateLink(ctx, e.user, late.ID); err != nil || !exp.Equal(rec.CreatedAt.Add(certs.PendingTTL)) {
		t.Fatalf("late link: expires %v, err %v", exp, err)
	}
}

func TestCancelledDeviceLinkIsDead(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	res, err := e.certs.Reserve(ctx, e.user, "Apple TV", "scep")
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := e.svc.CreateLink(ctx, e.user, res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CancelSCEPEnrolment(ctx, e.user.Sub, res.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ProfileByLink(ctx, code); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after cancel: err = %v, want ErrNotFound", err)
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{
		"KQ7M-2XRP": "KQ7M2XRP",
		"kq7m2xrp":  "KQ7M2XRP",
		"OIL0-1111": "01101111",
	} {
		if got, ok := normalizeCode(in); !ok || got != want {
			t.Errorf("normalizeCode(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

func TestRevokeAllCancelsPendingEnrolments(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, challenge := e.enrol(t)
	tv, err := e.certs.Reserve(ctx, e.user, "Apple TV", "scep")
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := e.svc.CreateLink(ctx, e.user, tv.ID)
	if err != nil {
		t.Fatal(err)
	}
	bob := store.User{Sub: "sub-bob", Email: "bob@example.com", Name: "Bob", LastLoginAt: e.clock}
	if err := e.st.UpsertUser(ctx, bob); err != nil {
		t.Fatal(err)
	}
	other, err := e.certs.Reserve(ctx, bob, "iPhone", "scep")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.certs.RevokeAll(ctx, e.user.Sub, "sub-admin"); err != nil {
		t.Fatal(err)
	}
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); resp.Allow {
		t.Fatal("a downloaded profile's challenge was allowed after revoke-all")
	}
	if _, err := e.svc.ProfileByLink(ctx, code); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device link after revoke-all: err = %v, want ErrNotFound", err)
	}
	for _, x := range []string{id, tv.ID} {
		if _, err := e.st.CertificateByID(ctx, x); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("pending record after revoke-all: err = %v, want ErrNotFound", err)
		}
	}
	if c, err := e.st.CertificateByID(ctx, other.ID); err != nil || c.Status != "pending" {
		t.Fatalf("other user's record: %+v, err %v; want pending", c, err)
	}
}

func TestRevokeAllKeepsIssuingEnrolmentTracked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, challenge := e.enrol(t)
	if _, resp, _ := post(t, e.svc.Challenge, challengeReq(challenge, "tx-1")); !resp.Allow {
		t.Fatal("challenge denied")
	}
	if _, err := e.certs.RevokeAll(ctx, e.user.Sub, "sub-admin"); err != nil {
		t.Fatal(err)
	}
	// step-ca signs the certificate it already accepted. The record must
	// become active so that an admin can see and revoke it.
	raw := issuedCert(t, e.user.Email, certs.DeviceURI(id))
	body := map[string]any{"scepTransactionID": "tx-1", "x509Certificate": map[string]any{"raw": raw}}
	if code, _, _ := post(t, e.svc.Notify, body); code != http.StatusOK {
		t.Fatalf("notify: %d", code)
	}
	if c, err := e.st.CertificateByID(ctx, id); err != nil || c.Status != "active" {
		t.Fatalf("record = %+v, err %v; want active", c, err)
	}
}
