// Package audit records security-relevant events in the database and in the
// structured log.
package audit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/JeffResc/AuthStep/internal/store"
)

const (
	Login       = "login"
	LoginDenied = "login_denied"
	CertIssued  = "cert_issued"
	CertRevoked = "cert_revoked"
	CertFailed  = "cert_failed"
	// CertCancelled is an Apple enrolment cancelled before the device enrolled.
	CertCancelled   = "cert_request_cancelled"
	DefaultLimitSet = "limit_default_set"
	UserLimitSet    = "limit_user_set"
)

type Actor struct {
	Sub   string
	Email string
}

// Notifier is told about every recorded entry, e.g. to email people. It
// handles its own errors: the action has already happened.
type Notifier interface {
	AuditEvent(ctx context.Context, e store.AuditEntry)
}

type Recorder struct {
	store   *store.Store
	notify  Notifier // nil: no notifications
	trusted []netip.Prefix
	log     *slog.Logger
	now     func() time.Time
}

// New returns a Recorder. trusted lists the reverse proxies whose
// X-Forwarded-For header is believed when recording the client IP.
func New(st *store.Store, n Notifier, trusted []netip.Prefix, log *slog.Logger) *Recorder {
	return &Recorder{store: st, notify: n, trusted: trusted, log: log, now: time.Now}
}

// Record stores the event. target names what the action applied to, such as
// a certificate ID or a user's sub.
func (rec *Recorder) Record(r *http.Request, actor Actor, action, target string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	e := store.AuditEntry{
		Time: rec.now(), ActorSub: actor.Sub, ActorEmail: actor.Email,
		Action: action, Target: target, IP: ClientIP(r, rec.trusted), Details: details,
	}
	if err := rec.store.InsertAuditEntry(r.Context(), e); err != nil {
		return err
	}
	rec.log.Info("audit", "action", action, "actor_sub", actor.Sub, "actor_email", actor.Email,
		"target", target, "ip", e.IP, "details", details)
	if rec.notify != nil {
		rec.notify.AuditEvent(r.Context(), e)
	}
	return nil
}

// ClientIP is the TCP peer address, unless the peer is a trusted proxy. Then
// it is the rightmost X-Forwarded-For address that is not a trusted proxy:
// addresses further left were supplied by the client and can be forged. A hop
// that is not an IP address ends the walk and the peer address is used.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !isTrusted(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			hops = append(hops, strings.TrimSpace(part))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(hops[i])
		if err != nil {
			break
		}
		ip = ip.Unmap()
		if !isTrusted(ip, trusted) {
			return ip.String()
		}
	}
	return peer.String()
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
