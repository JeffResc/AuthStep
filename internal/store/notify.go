package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Email is a queued message.
type Email struct {
	ID       int64
	To       string
	Subject  string
	Body     string
	Attempts int
}

func (s *Store) EnqueueEmail(ctx context.Context, e Email, now time.Time) error {
	return enqueue(ctx, s.db, e, now)
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func enqueue(ctx context.Context, db execer, e Email, now time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO outbox (recipient, subject, body, created_at, next_attempt_at) VALUES (?, ?, ?, ?, ?)`,
		e.To, e.Subject, e.Body, now.Unix(), now.Unix())
	return err
}

// DueEmails returns up to limit unsent emails whose next attempt is due.
func (s *Store) DueEmails(ctx context.Context, now time.Time, limit int) ([]Email, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, recipient, subject, body, attempts FROM outbox
		WHERE next_attempt_at IS NOT NULL AND next_attempt_at <= ?
		ORDER BY next_attempt_at, id LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	// rows.Err below reports iteration errors; Close cannot add to them.
	defer func() { _ = rows.Close() }()
	var out []Email
	for rows.Next() {
		var e Email
		if err := rows.Scan(&e.ID, &e.To, &e.Subject, &e.Body, &e.Attempts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) MarkEmailSent(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE outbox SET sent_at = ?, next_attempt_at = NULL, attempts = attempts + 1, last_error = NULL WHERE id = ?`,
		now.Unix(), id)
	return err
}

// MarkEmailFailed records a failed attempt. A nil next gives up on the email.
func (s *Store) MarkEmailFailed(ctx context.Context, id int64, errText string, next *time.Time) error {
	var at any
	if next != nil {
		at = next.Unix()
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?`,
		errText, at, id)
	return err
}

// Expiring is an active certificate within the reminder window, with the
// thresholds already handled for it.
type Expiring struct {
	Enrolment
	Sent []int
}

// ExpiringCertificates returns active certificates that expire after now
// but no later than now+within.
func (s *Store) ExpiringCertificates(ctx context.Context, now time.Time, within time.Duration) ([]Expiring, error) {
	rows, err := s.db.QueryContext(ctx, enrolmentQuery+`
		WHERE c.status = 'active' AND c.not_after > ? AND c.not_after <= ?
		ORDER BY c.not_after`, now.Unix(), now.Add(within).Unix())
	if err != nil {
		return nil, err
	}
	var out []Expiring
	for rows.Next() {
		e, err := scanEnrolment(rows)
		if err != nil {
			return nil, errors.Join(err, rows.Close())
		}
		out = append(out, Expiring{Enrolment: *e})
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Sent, err = s.sentThresholds(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) sentThresholds(ctx context.Context, certID string) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT threshold_days FROM notifications_sent WHERE cert_id = ?`, certID)
	if err != nil {
		return nil, err
	}
	// rows.Err below reports iteration errors; Close cannot add to them.
	defer func() { _ = rows.Close() }()
	var out []int
	for rows.Next() {
		var d int
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// QueueReminder marks thresholds as handled for certID and, when email is
// not nil, queues it, in one transaction.
func (s *Store) QueueReminder(ctx context.Context, certID string, thresholds []int, email *Email, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, d := range thresholds {
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO notifications_sent (cert_id, threshold_days, sent_at) VALUES (?, ?, ?)`,
				certID, d, now.Unix()); err != nil {
				return err
			}
		}
		if email == nil {
			return nil
		}
		return enqueue(ctx, tx, *email, now)
	})
}

// UserEmail returns the email of the user with sub.
func (s *Store) UserEmail(ctx context.Context, sub string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE sub = ?`, sub).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}
