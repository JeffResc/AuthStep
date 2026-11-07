package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/JeffResc/AuthStep/internal/ca"
	"github.com/JeffResc/AuthStep/internal/store"
)

const (
	email = "alice@example.com"
	devID = "0b3c9a52-4f8e-4d4e-9d6b-2f0c8e7a1c55"
)

var devURI = DeviceURI(devID)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func p256(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func makeCSR(t *testing.T, key crypto.Signer, tmpl x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func good() x509.CertificateRequest {
	return x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		URIs:           []*url.URL{mustURL(devURI)},
	}
}

func TestValidateCSR(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		key    crypto.Signer
		modify func(*x509.CertificateRequest)
		ok     bool
	}{
		{"valid", nil, func(*x509.CertificateRequest) {}, true},
		{"other user's email as CN", nil, func(c *x509.CertificateRequest) { c.Subject.CommonName = "mallory@example.com" }, false},
		{"extra subject attribute", nil, func(c *x509.CertificateRequest) { c.Subject.Organization = []string{"Evil"} }, false},
		{"other email SAN", nil, func(c *x509.CertificateRequest) { c.EmailAddresses = []string{"mallory@example.com"} }, false},
		{"two email SANs", nil, func(c *x509.CertificateRequest) { c.EmailAddresses = append(c.EmailAddresses, "mallory@example.com") }, false},
		{"no email SAN", nil, func(c *x509.CertificateRequest) { c.EmailAddresses = nil }, false},
		{"other device URI", nil, func(c *x509.CertificateRequest) {
			c.URIs = []*url.URL{mustURL(DeviceURI("11111111-1111-4111-8111-111111111111"))}
		}, false},
		{"two URIs", nil, func(c *x509.CertificateRequest) { c.URIs = append(c.URIs, mustURL("https://evil.example")) }, false},
		{"DNS SAN", nil, func(c *x509.CertificateRequest) { c.DNSNames = []string{"internal.example.com"} }, false},
		{"IP SAN", nil, func(c *x509.CertificateRequest) { c.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")} }, false},
		{"extra extension", nil, func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}
		}, false},
		{"RSA key", rsaKey, func(*x509.CertificateRequest) {}, false},
		{"P-384 key", p384, func(*x509.CertificateRequest) {}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.key
			if key == nil {
				key = p256(t)
			}
			tmpl := good()
			tt.modify(&tmpl)
			err := ValidateCSR(makeCSR(t, key, tmpl), email, devURI)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && !errors.Is(err, ErrInvalidCSR) {
				t.Fatalf("err = %v, want ErrInvalidCSR", err)
			}
		})
	}
}

func TestValidateCSRRejectsBadSignature(t *testing.T) {
	csr := makeCSR(t, p256(t), good())
	csr.Signature[len(csr.Signature)-1] ^= 0xff
	if err := ValidateCSR(csr, email, devURI); !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("err = %v, want ErrInvalidCSR", err)
	}
}

// fakeSigner self-signs with a throwaway CA so tests do not need step-ca.
type fakeSigner struct {
	mu        sync.Mutex
	calls     int
	cn        string
	sans      []string
	serial    int64
	revoked   []string
	revokeErr func(serial string) error
}

func (f *fakeSigner) Revoke(_ context.Context, serial string, _ int, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		if err := f.revokeErr(serial); err != nil {
			return err
		}
	}
	f.revoked = append(f.revoked, serial)
	return nil
}

func (f *fakeSigner) Sign(_ context.Context, csrDER []byte, cn string, sans []string, validity time.Duration) (*ca.Signed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.cn, f.sans = cn, sans
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.serial++
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(f.serial), Subject: csr.Subject, NotBefore: now, NotAfter: now.Add(validity),
		EmailAddresses: csr.EmailAddresses, URIs: csr.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &ca.Signed{Leaf: leaf}, nil
}

type env struct {
	svc    *Service
	st     *store.Store
	signer *fakeSigner
	user   store.User
	clock  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	e := &env{st: st, signer: &fakeSigner{}, clock: time.Unix(1_800_000_000, 0)}
	e.svc = New(st, e.signer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.svc.now = func() time.Time { return e.clock }
	e.user = store.User{Sub: "sub-alice", Email: email, Name: "Alice", LastLoginAt: e.clock}
	if err := st.UpsertUser(context.Background(), e.user); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) csrFor(t *testing.T, r *Reservation) []byte {
	tmpl := good()
	tmpl.URIs = []*url.URL{mustURL(r.DeviceURI)}
	return makeCSR(t, p256(t), tmpl).Raw
}

func TestIssue(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r, err := e.svc.Reserve(ctx, e.user, "  Work laptop ", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if r.Email != email || r.DeviceURI != DeviceURI(r.ID) {
		t.Fatalf("reservation = %+v", r)
	}

	signed, err := e.svc.Issue(ctx, e.user, r.ID, e.csrFor(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if e.signer.cn != email || len(e.signer.sans) != 2 || e.signer.sans[0] != email || e.signer.sans[1] != r.DeviceURI {
		t.Fatalf("signer got cn=%q sans=%v", e.signer.cn, e.signer.sans)
	}

	list, err := e.svc.List(ctx, e.user)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Status != "active" || list[0].DeviceName != "Work laptop" || list[0].Serial != signed.Leaf.SerialNumber.String() {
		t.Fatalf("list = %+v", list)
	}

	// A reservation is used once.
	if _, err := e.svc.Issue(ctx, e.user, r.ID, e.csrFor(t, r)); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("second issue: err = %v, want ErrNotPending", err)
	}
	if e.signer.calls != 1 {
		t.Fatalf("signer called %d times, want 1", e.signer.calls)
	}
}

func TestIssueRejections(t *testing.T) {
	ctx := context.Background()

	t.Run("other user's reservation", func(t *testing.T) {
		e := newEnv(t)
		r, _ := e.svc.Reserve(ctx, e.user, "laptop", "browser")
		mallory := store.User{Sub: "sub-mallory", Email: "mallory@example.com", LastLoginAt: e.clock}
		if err := e.st.UpsertUser(ctx, mallory); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Issue(ctx, mallory, r.ID, e.csrFor(t, r)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("expired reservation", func(t *testing.T) {
		e := newEnv(t)
		r, _ := e.svc.Reserve(ctx, e.user, "laptop", "browser")
		e.clock = e.clock.Add(PendingTTL + time.Second)
		if _, err := e.svc.Issue(ctx, e.user, r.ID, e.csrFor(t, r)); !errors.Is(err, ErrReservationExpired) {
			t.Fatalf("err = %v, want ErrReservationExpired", err)
		}
	})

	t.Run("CSR for another reservation", func(t *testing.T) {
		e := newEnv(t)
		r1, _ := e.svc.Reserve(ctx, e.user, "laptop", "browser")
		r2, _ := e.svc.Reserve(ctx, e.user, "phone", "browser")
		if _, err := e.svc.Issue(ctx, e.user, r1.ID, e.csrFor(t, r2)); !errors.Is(err, ErrInvalidCSR) {
			t.Fatalf("err = %v, want ErrInvalidCSR", err)
		}
		if e.signer.calls != 0 {
			t.Fatal("signer was called for an invalid CSR")
		}
	})

	t.Run("garbage CSR", func(t *testing.T) {
		e := newEnv(t)
		r, _ := e.svc.Reserve(ctx, e.user, "laptop", "browser")
		if _, err := e.svc.Issue(ctx, e.user, r.ID, []byte("not a csr")); !errors.Is(err, ErrInvalidCSR) {
			t.Fatalf("err = %v, want ErrInvalidCSR", err)
		}
	})
}

func TestReserveDeviceName(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"", "   ", "tab\there", string(make([]rune, 65))} {
		if _, err := e.svc.Reserve(context.Background(), e.user, name, "browser"); !errors.Is(err, ErrInvalidDeviceName) {
			t.Errorf("Reserve(%q): err = %v, want ErrInvalidDeviceName", name, err)
		}
	}
}

func TestReserveLimit(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	// Two issued, three pending: the default limit of 5 is reached.
	for range 2 {
		r, err := e.svc.Reserve(ctx, e.user, "device", "browser")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Issue(ctx, e.user, r.ID, e.csrFor(t, r)); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if _, err := e.svc.Reserve(ctx, e.user, "device", "browser"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Reserve(ctx, e.user, "device", "browser"); !errors.Is(err, store.ErrLimitReached) {
		t.Fatalf("6th reservation: err = %v, want ErrLimitReached", err)
	}

	// Abandoned reservations stop counting once they expire.
	e.clock = e.clock.Add(PendingTTL + time.Second)
	if _, err := e.svc.Reserve(ctx, e.user, "device", "browser"); err != nil {
		t.Fatalf("after pending expiry: %v", err)
	}
}

func (e *env) issue(t *testing.T, name string) store.Certificate {
	t.Helper()
	ctx := context.Background()
	r, err := e.svc.Reserve(ctx, e.user, name, "browser")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Issue(ctx, e.user, r.ID, e.csrFor(t, r)); err != nil {
		t.Fatal(err)
	}
	c, err := e.st.UserCertificate(ctx, e.user.Sub, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return *c
}

func (e *env) status(t *testing.T, id string) string {
	t.Helper()
	c, err := e.st.CertificateByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c.Status
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.issue(t, "laptop")

	if err := e.svc.Revoke(ctx, &c, "sub-admin", UserReasons[0]); err != nil {
		t.Fatal(err)
	}
	if e.status(t, c.ID) != "revoked" || len(e.signer.revoked) != 1 || e.signer.revoked[0] != c.Serial {
		t.Fatalf("status %q, step-ca revoked %v", e.status(t, c.ID), e.signer.revoked)
	}

	// The caller's copy is stale; the store refuses a second revoke.
	if err := e.svc.Revoke(ctx, &c, "sub-admin", UserReasons[0]); !errors.Is(err, store.ErrNotActive) {
		t.Fatalf("second revoke: err = %v, want ErrNotActive", err)
	}
}

func TestRevokeCAFailureKeepsActive(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "laptop")
	e.signer.revokeErr = func(string) error { return &ca.Error{Status: http.StatusInternalServerError, Message: "boom"} }
	if err := e.svc.Revoke(context.Background(), &c, e.user.Sub, UserReasons[0]); err == nil {
		t.Fatal("revoke succeeded although step-ca failed")
	}
	if got := e.status(t, c.ID); got != "active" {
		t.Fatalf("status = %q, want active", got)
	}
}

func TestRevokeAlreadyRevokedInCA(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "laptop")
	e.signer.revokeErr = func(serial string) error {
		return &ca.Error{Status: http.StatusBadRequest, Message: "certificate with serial number '" + serial + "' is already revoked"}
	}
	if err := e.svc.Revoke(context.Background(), &c, e.user.Sub, UserReasons[0]); err != nil {
		t.Fatal(err)
	}
	if got := e.status(t, c.ID); got != "revoked" {
		t.Fatalf("status = %q, want revoked", got)
	}
}

func TestRevokeAll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.issue(t, "a"), e.issue(t, "b"), e.issue(t, "c")
	if _, err := e.svc.Reserve(ctx, e.user, "pending", "browser"); err != nil {
		t.Fatal(err)
	}

	// step-ca fails on the second certificate RevokeAll tries.
	calls := 0
	failed := ""
	e.signer.revokeErr = func(serial string) error {
		calls++
		if calls == 2 {
			failed = serial
			return &ca.Error{Status: http.StatusInternalServerError, Message: "boom"}
		}
		return nil
	}
	done, err := e.svc.RevokeAll(ctx, e.user.Sub, "sub-admin")
	if err == nil || len(done) != 1 {
		t.Fatalf("RevokeAll = %d done, err %v; want 1 done and an error", len(done), err)
	}
	revoked := 0
	for _, x := range []store.Certificate{a, b, c} {
		st := e.status(t, x.ID)
		if st == "revoked" {
			revoked++
		}
		if x.Serial == failed && st != "active" {
			t.Fatalf("the certificate step-ca failed on is %q, want active", st)
		}
	}
	if revoked != 1 || e.status(t, done[0].ID) != "revoked" {
		t.Fatalf("%d revoked, want 1: the one RevokeAll reported", revoked)
	}

	e.signer.revokeErr = nil
	if _, err := e.svc.RevokeAll(ctx, e.user.Sub, "sub-admin"); err != nil {
		t.Fatal(err)
	}
	for _, x := range []store.Certificate{a, b, c} {
		if got := e.status(t, x.ID); got != "revoked" {
			t.Fatalf("%s is %q, want revoked", x.DeviceName, got)
		}
	}
}

func TestReserveLimitUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	const attempts = 25
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		ok, hit int
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Reserve(ctx, e.user, "device", "browser")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrLimitReached):
				hit++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 5 || hit != attempts-5 {
		t.Fatalf("%d reservations succeeded and %d hit the limit; want 5 and %d", ok, hit, attempts-5)
	}
}

func TestLimitOverrides(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	one := 1
	if err := e.st.SetUserCertLimit(ctx, e.user.Sub, &one); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.user, "a", "browser"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.user, "b", "browser"); !errors.Is(err, store.ErrLimitReached) {
		t.Fatalf("override 1: err = %v, want ErrLimitReached", err)
	}

	// Back to the default, which an admin lowers to 2.
	if err := e.st.SetUserCertLimit(ctx, e.user.Sub, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetDefaultCertLimit(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.user, "b", "browser"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.user, "c", "browser"); !errors.Is(err, store.ErrLimitReached) {
		t.Fatalf("default 2: err = %v, want ErrLimitReached", err)
	}

	for _, bad := range []int{-1, 1001} {
		if err := e.st.SetDefaultCertLimit(ctx, bad); !errors.Is(err, store.ErrInvalidLimit) {
			t.Errorf("SetDefaultCertLimit(%d) = %v, want ErrInvalidLimit", bad, err)
		}
	}
}
