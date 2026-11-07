package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

// fakeCA stands in for step-ca's /1.0/sign endpoint and records the request.
type fakeCA struct {
	*httptest.Server
	got struct {
		CSR      string `json:"csr"`
		OTT      string `json:"ott"`
		NotAfter string `json:"notAfter"`
	}
	revoke struct {
		Serial     string `json:"serial"`
		OTT        string `json:"ott"`
		ReasonCode int    `json:"reasonCode"`
		Reason     string `json:"reason"`
		Passive    bool   `json:"passive"`
	}
	status int
}

func newFakeCA(t *testing.T) *fakeCA {
	f := &fakeCA{status: http.StatusCreated}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/1.0/revoke" {
			if err := json.NewDecoder(r.Body).Decode(&f.revoke); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		if r.URL.Path != "/1.0/sign" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&f.got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(f.status)
		if f.status != http.StatusCreated {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": f.status, "message": "nope"})
			return
		}
		block, _ := pem.Decode([]byte(f.got.CSR))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		leaf, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, key)
		inter, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		enc := func(der []byte) string {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"crt": enc(leaf), "ca": enc(inter), "certChain": []string{enc(leaf), enc(inter)}})
	}))
	t.Cleanup(f.Close)
	return f
}

func newClient(t *testing.T, f *fakeCA) (*Client, *jose.JSONWebKey) {
	t.Helper()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.crt")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := jose.EncryptJWK(jwk, []byte("provisioner-password"))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.jwe")
	if err := os.WriteFile(keyPath, []byte(compact+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{URL: f.URL + "/", RootPath: rootPath, Provisioner: "authstep-jwk", KeyPath: keyPath, KeyPassword: "provisioner-password"})
	if err != nil {
		t.Fatal(err)
	}
	return c, jwk
}

func csrDER(t *testing.T) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice@example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignToken(t *testing.T) {
	f := newFakeCA(t)
	c, jwk := newClient(t, f)
	csr := csrDER(t)
	sans := []string{"alice@example.com", "urn:authstep:device:abc"}

	signed, err := c.Sign(context.Background(), csr, "alice@example.com", sans, 8760*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Leaf.SerialNumber.Int64() != 42 || len(signed.Chain) != 1 {
		t.Fatalf("signed = serial %v, chain %d", signed.Leaf.SerialNumber, len(signed.Chain))
	}
	if f.got.NotAfter != "8760h0m0s" {
		t.Fatalf("notAfter = %q", f.got.NotAfter)
	}

	tok, err := jose.ParseSigned(f.got.OTT)
	if err != nil {
		t.Fatal(err)
	}
	if kid := tok.Headers[0].KeyID; kid != jwk.KeyID {
		t.Fatalf("kid = %q, want %q", kid, jwk.KeyID)
	}
	var std jose.Claims
	var extra struct {
		SANs []string          `json:"sans"`
		SHA  string            `json:"sha"`
		CNF  map[string]string `json:"cnf"`
	}
	if err := tok.Claims(jwk.Public(), &std, &extra); err != nil {
		t.Fatalf("token signature: %v", err)
	}
	sum := sha256.Sum256(csr)
	root := sha256.Sum256(f.Certificate().Raw)
	switch {
	case std.Issuer != "authstep-jwk":
		t.Errorf("iss = %q", std.Issuer)
	case std.Subject != "alice@example.com":
		t.Errorf("sub = %q", std.Subject)
	case len(std.Audience) != 1 || std.Audience[0] != f.URL+"/1.0/sign":
		t.Errorf("aud = %v", std.Audience)
	case std.ID == "":
		t.Error("missing jti")
	case len(extra.SANs) != 2 || extra.SANs[0] != sans[0] || extra.SANs[1] != sans[1]:
		t.Errorf("sans = %v", extra.SANs)
	case extra.CNF["x5rt#S256"] != base64.RawURLEncoding.EncodeToString(sum[:]):
		t.Errorf("cnf = %v", extra.CNF)
	case extra.SHA != hex.EncodeToString(root[:]):
		t.Errorf("sha = %q", extra.SHA)
	}
}

func TestSignError(t *testing.T) {
	f := newFakeCA(t)
	f.status = http.StatusForbidden
	c, _ := newClient(t, f)
	_, err := c.Sign(context.Background(), csrDER(t), "alice@example.com", nil, time.Hour)
	var caErr *Error
	if !errors.As(err, &caErr) || caErr.Status != http.StatusForbidden || caErr.Message != "nope" {
		t.Fatalf("err = %v, want *Error 403 nope", err)
	}
}

func TestNewRejectsWrongPassword(t *testing.T) {
	f := newFakeCA(t)
	dir := t.TempDir()
	jwk, _ := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	jwe, _ := jose.EncryptJWK(jwk, []byte("right"))
	compact, _ := jwe.CompactSerialize()
	keyPath := filepath.Join(dir, "key.jwe")
	rootPath := filepath.Join(dir, "root.crt")
	if err := os.WriteFile(keyPath, []byte(compact), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{URL: f.URL, RootPath: rootPath, Provisioner: "p", KeyPath: keyPath, KeyPassword: "wrong"}); err == nil {
		t.Fatal("New accepted a wrong provisioner password")
	}
}

func TestRevoke(t *testing.T) {
	f := newFakeCA(t)
	c, jwk := newClient(t, f)
	if err := c.Revoke(context.Background(), "12345", 5, "cessationOfOperation"); err != nil {
		t.Fatal(err)
	}
	got := f.revoke
	if got.Serial != "12345" || !got.Passive || got.ReasonCode != 5 || got.Reason != "cessationOfOperation" {
		t.Fatalf("request = %+v", got)
	}
	tok, err := jose.ParseSigned(got.OTT)
	if err != nil {
		t.Fatal(err)
	}
	var std jose.Claims
	if err := tok.Claims(jwk.Public(), &std); err != nil {
		t.Fatal(err)
	}
	// step-ca requires the token subject to equal the serial.
	if std.Subject != "12345" || len(std.Audience) != 1 || std.Audience[0] != f.URL+"/1.0/revoke" {
		t.Fatalf("claims = sub %q aud %v", std.Subject, std.Audience)
	}
}
