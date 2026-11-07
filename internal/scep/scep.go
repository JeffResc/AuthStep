// Package scep issues one-time SCEP challenges inside signed Apple profiles
// and answers step-ca's SCEPCHALLENGE and NOTIFYING webhooks.
package scep

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/keypair"
	"github.com/JeffResc/AuthStep/internal/mobileconfig"
	"github.com/JeffResc/AuthStep/internal/store"
)

const maxWebhookBody = 64 << 10

var ErrNotSCEP = errors.New("certificate is not a pending SCEP enrolment")

type Service struct {
	store   *store.Store
	audit   *audit.Recorder
	signer  *keypair.File
	scepURL string
	log     *slog.Logger
	now     func() time.Time
}

func New(st *store.Store, rec *audit.Recorder, signer *keypair.File, scepURL string, log *slog.Logger) *Service {
	return &Service{store: st, audit: rec, signer: signer, scepURL: scepURL, log: log, now: time.Now}
}

// Profile creates the record's one challenge and returns the signed profile
// carrying it. A second call for the same record fails with
// store.ErrChallengeExists: the challenge is never shown twice.
func (s *Service) Profile(ctx context.Context, user store.User, certID string) ([]byte, error) {
	rec, err := s.store.UserCertificate(ctx, user.Sub, certID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if rec.Method != "scep" || rec.Status != "pending" {
		return nil, ErrNotSCEP
	}
	if now.Sub(rec.CreatedAt) > certs.PendingTTL {
		return nil, certs.ErrReservationExpired
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.store.CreateSCEPChallenge(ctx, certID, hashChallenge(challenge), now.Add(certs.ChallengeTTL)); err != nil {
		return nil, err
	}

	payloadUUID, err := certs.NewUUID()
	if err != nil {
		return nil, err
	}
	body, err := mobileconfig.Build(mobileconfig.SCEPProfile{
		ProfileUUID: certID, PayloadUUID: payloadUUID, DeviceName: rec.DeviceName, URL: s.scepURL,
		Challenge: challenge, Email: user.Email, DeviceURI: certs.DeviceURI(certID),
	})
	if err != nil {
		return nil, err
	}
	pair, chain, err := s.signer.Chain()
	if err != nil {
		return nil, err
	}
	return mobileconfig.Sign(body, pair.Leaf, chain, pair.PrivateKey)
}

func hashChallenge(c string) string {
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}

// webhookRequest holds the fields step-ca sends to SCEP webhooks.
type webhookRequest struct {
	SCEPChallenge        string `json:"scepChallenge"`
	SCEPTransactionID    string `json:"scepTransactionID"`
	SCEPErrorCode        int    `json:"scepErrorCode"`
	SCEPErrorDescription string `json:"scepErrorDescription"`
	X509Certificate      *struct {
		Raw []byte `json:"raw"`
	} `json:"x509Certificate"`
}

type webhookResponse struct {
	Allow bool `json:"allow"`
	Data  any  `json:"data,omitempty"`
}

// ChallengeData is what the step-ca SCEP template reads as .Webhooks.<name>.
type ChallengeData struct {
	Email     string `json:"email"`
	DeviceURI string `json:"deviceURI"`
}

// Challenge answers step-ca's SCEPCHALLENGE webhook. Errors that step-ca
// should retry return 500; everything else is a definite allow or deny.
func (s *Service) Challenge(w http.ResponseWriter, r *http.Request) {
	req, ok := decode(w, r)
	if !ok {
		return
	}
	if req.SCEPChallenge == "" || req.SCEPTransactionID == "" {
		s.deny(w, "missing challenge or transaction ID")
		return
	}
	e, err := s.store.ConsumeSCEPChallenge(r.Context(), hashChallenge(req.SCEPChallenge), req.SCEPTransactionID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrChallengeExpired),
		errors.Is(err, store.ErrChallengeUsed), errors.Is(err, store.ErrNotPending):
		s.deny(w, err.Error(), "transaction", req.SCEPTransactionID)
		return
	case err != nil:
		s.log.Error("scep challenge", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Info("scep challenge accepted", "id", e.ID, "sub", e.UserSub, "transaction", req.SCEPTransactionID)
	writeJSON(w, webhookResponse{Allow: true, Data: ChallengeData{Email: e.Email, DeviceURI: certs.DeviceURI(e.ID)}})
}

func (s *Service) deny(w http.ResponseWriter, reason string, kv ...any) {
	s.log.Warn("scep challenge denied", append([]any{"reason", reason}, kv...)...)
	writeJSON(w, webhookResponse{Allow: false})
}

// Notify answers step-ca's NOTIFYING webhook, which reports the outcome of
// an enrolment. step-ca ignores the response; the record is what matters.
func (s *Service) Notify(w http.ResponseWriter, r *http.Request) {
	req, ok := decode(w, r)
	if !ok {
		return
	}
	e, err := s.store.EnrolmentByTransaction(r.Context(), req.SCEPTransactionID)
	if errors.Is(err, store.ErrNotFound) {
		s.log.Warn("scep notification for unknown transaction", "transaction", req.SCEPTransactionID)
		writeJSON(w, webhookResponse{Allow: true})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	owner := audit.Actor{Sub: e.UserSub, Email: e.Email}

	if req.X509Certificate == nil {
		if err := s.store.FailCertificate(r.Context(), e.ID); err != nil && !errors.Is(err, store.ErrNotPending) {
			s.fail(w, err)
			return
		}
		if err := s.audit.Record(r, owner, audit.CertFailed, e.ID, map[string]any{
			"method": "scep", "code": req.SCEPErrorCode, "description": req.SCEPErrorDescription,
		}); err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, webhookResponse{Allow: true})
		return
	}

	crt, err := x509.ParseCertificate(req.X509Certificate.Raw)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The step-ca template builds the identity from our challenge response,
	// so a mismatch means step-ca is misconfigured.
	uri := certs.DeviceURI(e.ID)
	if !hasURI(crt, uri) || !slices.Contains(crt.EmailAddresses, e.Email) {
		s.log.Error("scep certificate does not carry the expected identity; check the step-ca SCEP template",
			"id", e.ID, "serial", crt.SerialNumber.String(), "want_uri", uri, "want_email", e.Email)
	}
	serial := crt.SerialNumber.String()
	if e.Status == "active" && e.Serial == serial {
		writeJSON(w, webhookResponse{Allow: true}) // duplicate notification
		return
	}
	if err := s.store.ActivateCertificate(r.Context(), e.ID, serial, crt.NotBefore, crt.NotAfter); err != nil {
		s.log.Error("issued certificate not recorded", "id", e.ID, "serial", serial, "sub", e.UserSub, "err", err)
		s.fail(w, err)
		return
	}
	if err := s.audit.Record(r, owner, audit.CertIssued, e.ID, map[string]any{
		"method": "scep", "serial": serial, "not_after": crt.NotAfter.UTC(),
	}); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, webhookResponse{Allow: true})
}

func (s *Service) fail(w http.ResponseWriter, err error) {
	s.log.Error("scep notification", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func hasURI(crt *x509.Certificate, uri string) bool {
	for _, u := range crt.URIs {
		if u.String() == uri {
			return true
		}
	}
	return false
}

func decode(w http.ResponseWriter, r *http.Request) (*webhookRequest, bool) {
	var req webhookRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebhookBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	return &req, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// RequireCA allows only requests whose verified client certificate names
// caHost, i.e. step-ca's own TLS certificate.
func RequireCA(caHost string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].VerifyHostname(caHost) != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
