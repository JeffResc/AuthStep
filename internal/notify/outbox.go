package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/JeffResc/AuthStep/internal/store"
)

const (
	outboxInterval = 10 * time.Second
	outboxBatch    = 50
	maxAttempts    = 8
	maxBackoff     = 6 * time.Hour
)

// Outbox sends queued emails and retries failures with backoff.
type Outbox struct {
	store  *store.Store
	mailer Mailer
	log    *slog.Logger
	now    func() time.Time
}

func NewOutbox(st *store.Store, m Mailer, log *slog.Logger) *Outbox {
	return &Outbox{store: st, mailer: m, log: log, now: time.Now}
}

// Run sends due emails every few seconds until ctx ends.
func (o *Outbox) Run(ctx context.Context) {
	t := time.NewTicker(outboxInterval)
	defer t.Stop()
	for {
		if err := o.Flush(ctx); err != nil {
			o.log.Error("outbox", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Flush sends the emails that are due now.
func (o *Outbox) Flush(ctx context.Context) error {
	emails, err := o.store.DueEmails(ctx, o.now(), outboxBatch)
	if err != nil {
		return err
	}
	for _, e := range emails {
		sendErr := o.mailer.Send(ctx, e.To, e.Subject, e.Body)
		if sendErr == nil {
			if err := o.store.MarkEmailSent(ctx, e.ID, o.now()); err != nil {
				return err
			}
			continue
		}
		var next *time.Time
		if e.Attempts+1 < maxAttempts {
			t := o.now().Add(backoff(e.Attempts))
			next = &t
			o.log.Warn("email not sent; will retry", "id", e.ID, "to", e.To, "attempt", e.Attempts+1, "retry_at", t, "err", sendErr)
		} else {
			o.log.Error("email not sent; giving up", "id", e.ID, "to", e.To, "attempts", e.Attempts+1, "err", sendErr)
		}
		if err := o.store.MarkEmailFailed(ctx, e.ID, sendErr.Error(), next); err != nil {
			return err
		}
	}
	return nil
}

// backoff is 1 minute doubled per earlier attempt, at most maxBackoff.
func backoff(attempts int) time.Duration {
	d := time.Minute << attempts
	if d <= 0 || d > maxBackoff {
		return maxBackoff
	}
	return d
}
