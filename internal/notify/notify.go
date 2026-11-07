// Package notify queues emails: audit-event notices for certificate owners
// and an admin address, and certificate expiry reminders.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/JeffResc/AuthStep/internal/store"
)

// Thresholds are the days before expiry at which owners are reminded.
var Thresholds = []int{30, 7, 1}

const reminderInterval = time.Hour

type Notifier struct {
	store      *store.Store
	baseURL    string
	adminEmail string // empty: no admin emails
	log        *slog.Logger
	now        func() time.Time
}

func New(st *store.Store, baseURL, adminEmail string, log *slog.Logger) *Notifier {
	return &Notifier{store: st, baseURL: baseURL, adminEmail: adminEmail, log: log, now: time.Now}
}

// AuditEvent queues the emails for one audit entry. The action it describes
// has already happened, so failures are logged and not returned.
func (n *Notifier) AuditEvent(ctx context.Context, e store.AuditEntry) {
	if n.adminEmail != "" {
		n.queue(ctx, store.Email{To: n.adminEmail, Subject: adminSubject(e), Body: adminBody(e, n.baseURL)})
	}
	switch e.Action {
	case "cert_issued", "cert_revoked":
	default:
		return
	}
	c, err := n.store.CertificateByID(ctx, e.Target)
	if err != nil {
		n.log.Error("owner notification: load certificate", "id", e.Target, "err", err)
		return
	}
	owner, err := n.store.UserEmail(ctx, c.UserSub)
	if err != nil {
		n.log.Error("owner notification: load owner", "sub", c.UserSub, "err", err)
		return
	}
	if e.Action == "cert_issued" {
		n.queue(ctx, store.Email{
			To:      owner,
			Subject: fmt.Sprintf("New certificate for %s", c.DeviceName),
			Body: fmt.Sprintf(`A client certificate was issued for your account.

Device:  %s
Expires: %s
Serial:  %s

If you did not request it, revoke it now at %s and tell your administrator.
`, c.DeviceName, c.NotAfter.UTC().Format("2 Jan 2006"), c.Serial, n.baseURL),
		})
		return
	}
	by := "You revoked it."
	if e.ActorSub != c.UserSub {
		by = fmt.Sprintf("It was revoked by an administrator (%s).", e.ActorEmail)
	}
	n.queue(ctx, store.Email{
		To:      owner,
		Subject: fmt.Sprintf("Certificate revoked for %s", c.DeviceName),
		Body: fmt.Sprintf(`A client certificate on your account was revoked. %s

Device: %s
Reason: %v
Serial: %s

Services that check revocation no longer accept it. Manage your certificates at %s.
`, by, c.DeviceName, e.Details["reason"], c.Serial, n.baseURL),
	})
}

func (n *Notifier) queue(ctx context.Context, e store.Email) {
	if err := n.store.EnqueueEmail(ctx, e, n.now()); err != nil {
		n.log.Error("queue email", "to", e.To, "subject", e.Subject, "err", err)
	}
}

func adminSubject(e store.AuditEntry) string {
	actor := e.ActorEmail
	if actor == "" {
		actor = e.ActorSub
	}
	return fmt.Sprintf("[AuthStep] %s by %s", e.Action, actor)
}

func adminBody(e store.AuditEntry, baseURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Action: %s\nActor:  %s (%s)\nTarget: %s\nIP:     %s\nTime:   %s\n",
		e.Action, e.ActorEmail, e.ActorSub, e.Target, e.IP, e.Time.UTC().Format(time.RFC3339))
	keys := make([]string, 0, len(e.Details))
	for k := range e.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, _ := json.Marshal(e.Details[k])
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	fmt.Fprintf(&b, "\nAudit log: %s/admin/audit\n", baseURL)
	return b.String()
}

// RunReminders checks for expiring certificates every hour until ctx ends.
func (n *Notifier) RunReminders(ctx context.Context) {
	t := time.NewTicker(reminderInterval)
	defer t.Stop()
	for {
		if err := n.RemindExpiring(ctx); err != nil {
			n.log.Error("expiry reminders", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RemindExpiring sends one reminder per threshold a certificate crosses. If
// several thresholds were crossed since the last run (for example after
// downtime), only one email goes out and all of them are marked.
func (n *Notifier) RemindExpiring(ctx context.Context) error {
	now := n.now()
	certs, err := n.store.ExpiringCertificates(ctx, now, time.Duration(slices.Max(Thresholds))*24*time.Hour)
	if err != nil {
		return err
	}
	for _, c := range certs {
		left := c.NotAfter.Sub(now)
		var crossed []int
		newlyCrossed := false
		for _, d := range Thresholds {
			if left <= time.Duration(d)*24*time.Hour {
				crossed = append(crossed, d)
				newlyCrossed = newlyCrossed || !slices.Contains(c.Sent, d)
			}
		}
		if !newlyCrossed {
			continue
		}
		days := int(math.Ceil(left.Hours() / 24))
		email := &store.Email{
			To:      c.Email,
			Subject: fmt.Sprintf("Certificate for %s expires in %s", c.DeviceName, plural(days, "day")),
			Body: fmt.Sprintf(`Your client certificate for %s expires on %s.

Create a new certificate for this device before then at %s and install it. After it expires, services stop accepting the old one.
`, c.DeviceName, c.NotAfter.UTC().Format("2 Jan 2006 15:04 UTC"), n.baseURL),
		}
		if err := n.store.QueueReminder(ctx, c.ID, crossed, email, now); err != nil {
			return err
		}
	}
	return nil
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
