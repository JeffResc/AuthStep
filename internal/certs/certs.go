// Package certs implements browser certificate issuance: reserving a device
// record, validating the browser's CSR and signing it through step-ca.
package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/JeffResc/AuthStep/internal/ca"
	"github.com/JeffResc/AuthStep/internal/store"
)

const (
	Validity   = 365 * 24 * time.Hour
	PendingTTL = 15 * time.Minute
	// ChallengeTTL is how long a downloaded Apple profile can enrol.
	ChallengeTTL    = 15 * time.Minute
	DeviceURIPrefix = "urn:authstep:device:"
	maxDeviceName   = 64
)

var (
	ErrInvalidDeviceName  = errors.New("device name must be 1 to 64 printable characters")
	ErrReservationExpired = errors.New("this request expired; start again")
	ErrInvalidCSR         = errors.New("invalid certificate request")
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// CA is the part of the step-ca client the service uses.
type CA interface {
	Sign(ctx context.Context, csrDER []byte, cn string, sans []string, validity time.Duration) (*ca.Signed, error)
	Revoke(ctx context.Context, serial string, reasonCode int, reason string) error
}

type Service struct {
	store *store.Store
	ca    CA
	log   *slog.Logger
	now   func() time.Time
}

func New(st *store.Store, c CA, log *slog.Logger) *Service {
	return &Service{store: st, ca: c, log: log, now: time.Now}
}

// Reservation tells the browser exactly what its CSR must contain.
type Reservation struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	DeviceURI string `json:"deviceURI"`
}

func DeviceURI(id string) string { return DeviceURIPrefix + id }

// Reserve creates a pending certificate record for a new device. method is
// "browser" or "scep".
func (s *Service) Reserve(ctx context.Context, user store.User, deviceName, method string) (*Reservation, error) {
	name := strings.TrimSpace(deviceName)
	if !validDeviceName(name) {
		return nil, ErrInvalidDeviceName
	}
	id, err := NewUUID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	err = s.store.ReserveCertificate(ctx, store.Certificate{ID: id, UserSub: user.Sub, DeviceName: name, Method: method}, now, now.Add(-PendingTTL))
	if err != nil {
		return nil, err
	}
	return &Reservation{ID: id, Email: user.Email, DeviceURI: DeviceURI(id)}, nil
}

// Issue validates csrDER against the reservation and the user's identity and
// has step-ca sign it.
func (s *Service) Issue(ctx context.Context, user store.User, id string, csrDER []byte) (*ca.Signed, error) {
	rec, err := s.store.UserCertificate(ctx, user.Sub, id)
	if err != nil {
		return nil, err
	}
	if rec.Status != "pending" || rec.Method != "browser" {
		return nil, store.ErrNotPending
	}
	if s.now().Sub(rec.CreatedAt) > PendingTTL {
		return nil, ErrReservationExpired
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	uri := DeviceURI(id)
	if err := ValidateCSR(csr, user.Email, uri); err != nil {
		return nil, err
	}

	signed, err := s.ca.Sign(ctx, csr.Raw, user.Email, []string{user.Email, uri}, Validity)
	if err != nil {
		return nil, err
	}
	serial := signed.Leaf.SerialNumber.String()
	if err := s.store.ActivateCertificate(ctx, id, serial, signed.Leaf.NotBefore, signed.Leaf.NotAfter); err != nil {
		// The certificate exists in step-ca but not here. Log enough to revoke it.
		s.log.Error("issued certificate not recorded", "id", id, "serial", serial, "sub", user.Sub, "err", err)
		return nil, err
	}
	s.log.Info("certificate issued", "id", id, "serial", serial, "sub", user.Sub, "device", rec.DeviceName)
	return signed, nil
}

// ValidateCSR accepts only a P-256 CSR whose subject is exactly CN=email and
// whose only extension is a SAN with exactly email and deviceURI.
func ValidateCSR(csr *x509.CertificateRequest, email, deviceURI string) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidCSR, fmt.Sprintf(format, a...))
	}
	if err := csr.CheckSignature(); err != nil {
		return bad("signature: %v", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return bad("key must be ECDSA P-256")
	}
	if len(csr.Subject.Names) != 1 || csr.Subject.CommonName != email {
		return bad("subject must be exactly CN=%s", email)
	}
	if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 {
		return bad("DNS and IP names are not allowed")
	}
	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != email {
		return bad("email SAN must be exactly %s", email)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != deviceURI {
		return bad("URI SAN must be exactly %s", deviceURI)
	}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			return bad("extension %s is not allowed", ext.Id)
		}
	}
	return nil
}

func validDeviceName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > maxDeviceName {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// NewUUID returns a random (version 4) UUID.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// List returns the user's certificates, newest first. Pending browser
// reservations are left out: the browser finishes them in one step. Pending
// Apple enrolments are kept while they can still complete, which is at most
// PendingTTL to download the profile plus ChallengeTTL to install it.
func (s *Service) List(ctx context.Context, user store.User) ([]store.Certificate, error) {
	all, err := s.store.ListUserCertificates(ctx, user.Sub)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := all[:0]
	for _, c := range all {
		if c.Status != "pending" || c.Method == "scep" && now.Sub(c.CreatedAt) < PendingTTL+ChallengeTTL {
			out = append(out, c)
		}
	}
	return out, nil
}

// Reason is an RFC 5280 revocation reason.
type Reason struct {
	Code  int
	Name  string
	Label string
}

// UserReasons are the reasons offered when revoking a single certificate.
var UserReasons = []Reason{
	{5, "cessationOfOperation", "I no longer use this device"},
	{1, "keyCompromise", "The device was lost, stolen or compromised"},
	{4, "superseded", "It was replaced by a new certificate"},
}

// ReasonOffboarded is used when an admin revokes all of a user's certificates.
var ReasonOffboarded = Reason{3, "affiliationChanged", "User offboarded"}

func ReasonByName(name string) (Reason, bool) {
	for _, r := range UserReasons {
		if r.Name == name {
			return r, true
		}
	}
	return Reason{}, false
}

// Revoke revokes an active certificate in step-ca and records it.
func (s *Service) Revoke(ctx context.Context, c *store.Certificate, actorSub string, reason Reason) error {
	if c.Status != "active" {
		return store.ErrNotActive
	}
	if err := s.ca.Revoke(ctx, c.Serial, reason.Code, reason.Name); err != nil && !alreadyRevoked(err) {
		return err
	}
	if err := s.store.RevokeCertificate(ctx, c.ID, actorSub, reason.Name, s.now()); err != nil {
		return err
	}
	s.log.Info("certificate revoked", "id", c.ID, "serial", c.Serial, "owner", c.UserSub, "by", actorSub, "reason", reason.Name)
	return nil
}

// RevokeAll revokes every active certificate of userSub. It stops at the
// first failure and returns the certificates revoked so far.
func (s *Service) RevokeAll(ctx context.Context, userSub, actorSub string) ([]store.Certificate, error) {
	all, err := s.store.ListUserCertificates(ctx, userSub)
	if err != nil {
		return nil, err
	}
	var done []store.Certificate
	for _, c := range all {
		if c.Status != "active" {
			continue
		}
		if err := s.Revoke(ctx, &c, actorSub, ReasonOffboarded); err != nil {
			return done, err
		}
		done = append(done, c)
	}
	return done, nil
}

// alreadyRevoked reports step-ca's answer for a serial it has already
// revoked, which happens when an earlier attempt failed after step-ca
// revoked the serial but before AuthStep recorded it. step-ca has no error
// code for this, so the message is matched.
func alreadyRevoked(err error) bool {
	var caErr *ca.Error
	return errors.As(err, &caErr) && caErr.Status == http.StatusBadRequest && strings.Contains(caErr.Message, "is already revoked")
}
