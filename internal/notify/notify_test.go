package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JeffResc/AuthStep/internal/store"
)

const (
	owner = "alice@example.com"
	admin = "security@example.com"
)

type env struct {
	st    *store.Store
	n     *Notifier
	clock time.Time
}

func newEnv(t *testing.T, adminEmail string) *env {
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
	e := &env{st: st, clock: time.Unix(1_800_000_000, 0)}
	e.n = New(st, "https://authstep.example.com", adminEmail, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.n.now = func() time.Time { return e.clock }
	for _, u := range []store.User{
		{Sub: "sub-alice", Email: owner, Name: "Alice", LastLoginAt: e.clock},
		{Sub: "sub-admin", Email: "boss@example.com", Name: "Boss", IsAdmin: true, LastLoginAt: e.clock},
	} {
		if err := st.UpsertUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// activeCert creates an active certificate for Alice that expires at notAfter.
func (e *env) activeCert(t *testing.T, id, device string, notAfter time.Time) {
	t.Helper()
	ctx := context.Background()
	c := store.Certificate{ID: id, UserSub: "sub-alice", DeviceName: device, Method: "browser"}
	if err := e.st.ReserveCertificate(ctx, c, e.clock, e.clock.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ActivateCertificate(ctx, id, "serial-"+id, e.clock, notAfter); err != nil {
		t.Fatal(err)
	}
}

// queued returns all queued emails, oldest first.
func (e *env) queued(t *testing.T) []store.Email {
	t.Helper()
	out, err := e.st.DueEmails(context.Background(), time.Unix(1<<40, 0), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRemindersEachThresholdOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "")
	expiry := e.clock.Add(31 * 24 * time.Hour)
	e.activeCert(t, "c1", "Work laptop", expiry)

	// Run the hourly job from 31 days before expiry until a day after it.
	for ; e.clock.Before(expiry.Add(24 * time.Hour)); e.clock = e.clock.Add(time.Hour) {
		if err := e.n.RemindExpiring(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := e.queued(t)
	want := []string{"in 30 days", "in 7 days", "in 1 day"}
	if len(got) != len(want) {
		t.Fatalf("%d reminders, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].To != owner || !strings.HasSuffix(got[i].Subject, w) || !strings.Contains(got[i].Subject, "Work laptop") {
			t.Errorf("reminder %d = to %s, %q; want %q", i, got[i].To, got[i].Subject, w)
		}
	}
}

func TestRemindersAfterDowntimeSendOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "")
	expiry := e.clock.Add(6 * 24 * time.Hour) // 30 and 7 days are already crossed
	e.activeCert(t, "c1", "Phone", expiry)

	for range 3 {
		if err := e.n.RemindExpiring(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.queued(t); len(got) != 1 || !strings.HasSuffix(got[0].Subject, "in 6 days") {
		t.Fatalf("got %+v, want one reminder 'in 6 days'", got)
	}

	e.clock = expiry.Add(-12 * time.Hour)
	if err := e.n.RemindExpiring(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.queued(t); len(got) != 2 || !strings.HasSuffix(got[1].Subject, "in 1 day") {
		t.Fatalf("got %+v, want a second reminder 'in 1 day'", got)
	}
}

func TestNoRemindersForRevokedOrExpired(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "")
	e.activeCert(t, "revoked", "Old phone", e.clock.Add(5*24*time.Hour))
	if err := e.st.RevokeCertificate(ctx, "revoked", "sub-alice", "superseded", e.clock); err != nil {
		t.Fatal(err)
	}
	e.activeCert(t, "expired", "Old laptop", e.clock.Add(time.Hour))
	e.clock = e.clock.Add(2 * time.Hour)
	if err := e.n.RemindExpiring(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.queued(t); len(got) != 0 {
		t.Fatalf("got %+v, want no reminders", got)
	}
}

func entry(action, actorSub, actorEmail, target string, details map[string]any) store.AuditEntry {
	return store.AuditEntry{Time: time.Unix(1_800_000_000, 0), ActorSub: actorSub, ActorEmail: actorEmail,
		Action: action, Target: target, IP: "10.0.0.1", Details: details}
}

func recipients(emails []store.Email) []string {
	var out []string
	for _, e := range emails {
		out = append(out, e.To)
	}
	return out
}

func TestAuditEmailRecipients(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		admin string
		entry store.AuditEntry
		want  []string
	}{
		{"issued, with admin address", admin, entry("cert_issued", "sub-alice", owner, "c1", map[string]any{"serial": "serial-c1"}), []string{admin, owner}},
		{"revoked by admin", admin, entry("cert_revoked", "sub-admin", "boss@example.com", "c1", map[string]any{"reason": "affiliationChanged"}), []string{admin, owner}},
		{"login goes to admin only", admin, entry("login", "sub-alice", owner, "sub-alice", nil), []string{admin}},
		{"denied login goes to admin only", admin, entry("login_denied", "sub-x", "x@example.com", "sub-x", map[string]any{"reason": "not in issuer group"}), []string{admin}},
		{"limit change goes to admin only", admin, entry("limit_default_set", "sub-admin", "boss@example.com", "default", map[string]any{"limit": 3}), []string{admin}},
		{"issued, no admin address", "", entry("cert_issued", "sub-alice", owner, "c1", nil), []string{owner}},
		{"login, no admin address", "", entry("login", "sub-alice", owner, "sub-alice", nil), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.admin)
			e.activeCert(t, "c1", "Work laptop", e.clock.Add(365*24*time.Hour))
			e.n.AuditEvent(ctx, tt.entry)
			got := recipients(e.queued(t))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("recipients = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRevokeEmailNamesWhoRevoked(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		actor, actorEmail, want string
	}{
		{"sub-alice", owner, "You revoked it."},
		{"sub-admin", "boss@example.com", "revoked by an administrator (boss@example.com)"},
	} {
		e := newEnv(t, "")
		e.activeCert(t, "c1", "Work laptop", e.clock.Add(365*24*time.Hour))
		e.n.AuditEvent(ctx, entry("cert_revoked", tt.actor, tt.actorEmail, "c1", map[string]any{"reason": "keyCompromise"}))
		got := e.queued(t)
		if len(got) != 1 || !strings.Contains(got[0].Body, tt.want) || !strings.Contains(got[0].Body, "keyCompromise") {
			t.Fatalf("revoked by %s: %+v", tt.actor, got)
		}
	}
}

type fakeMailer struct {
	fail int // fail this many sends, then succeed
	sent []string
}

func (f *fakeMailer) Send(_ context.Context, to, _, _ string) error {
	if f.fail > 0 {
		f.fail--
		return errors.New("smtp down")
	}
	f.sent = append(f.sent, to)
	return nil
}

func TestOutboxRetries(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "")
	m := &fakeMailer{fail: 2}
	o := NewOutbox(e.st, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	o.now = func() time.Time { return e.clock }
	if err := e.st.EnqueueEmail(ctx, store.Email{To: owner, Subject: "s", Body: "b"}, e.clock); err != nil {
		t.Fatal(err)
	}

	flush := func() {
		t.Helper()
		if err := o.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	flush() // attempt 1 fails; retry in 1 minute
	flush() // not due yet
	if m.fail != 1 {
		t.Fatalf("retried before the backoff elapsed")
	}
	e.clock = e.clock.Add(time.Minute)
	flush() // attempt 2 fails; retry in 2 minutes
	e.clock = e.clock.Add(2 * time.Minute)
	flush() // attempt 3 succeeds
	flush()
	if len(m.sent) != 1 {
		t.Fatalf("sent %d times, want once", len(m.sent))
	}
}

func TestOutboxGivesUp(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "")
	m := &fakeMailer{fail: 1 << 30}
	o := NewOutbox(e.st, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	o.now = func() time.Time { return e.clock }
	if err := e.st.EnqueueEmail(ctx, store.Email{To: owner, Subject: "s", Body: "b"}, e.clock); err != nil {
		t.Fatal(err)
	}
	for range maxAttempts + 3 {
		if err := o.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		e.clock = e.clock.Add(maxBackoff)
	}
	if attempts := (1 << 30) - m.fail; attempts != maxAttempts {
		t.Fatalf("%d attempts, want %d", attempts, maxAttempts)
	}
	if got := e.queued(t); len(got) != 0 {
		t.Fatalf("email still queued after giving up: %+v", got)
	}
}

func TestMessageHeaders(t *testing.T) {
	from := mail.Address{Name: "AuthStep", Address: "authstep@example.com"}
	to := mail.Address{Address: owner}
	msg, err := message(from, to, "Certificate for Café\r\nBcc: evil@example.com", "Line one\nŁine two")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Bcc") != "" {
		t.Fatal("subject injected a Bcc header")
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Certificate for Café  Bcc: evil@example.com" {
		t.Fatalf("subject = %q", subject)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if string(body) != "Line one\r\nŁine two" {
		t.Fatalf("body = %q", body)
	}
}
