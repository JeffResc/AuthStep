package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrChallengeExists  = errors.New("a challenge was already issued for this certificate")
	ErrChallengeExpired = errors.New("challenge expired")
	ErrChallengeUsed    = errors.New("challenge already used by another enrolment")
)

// CreateSCEPChallenge stores the hash of the one challenge a pending SCEP
// record gets.
func (s *Store) CreateSCEPChallenge(ctx context.Context, certID, hash string, expires time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scep_challenges WHERE cert_id = ?`, certID).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return ErrChallengeExists
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO scep_challenges (cert_id, challenge_hash, expires_at) VALUES (?, ?, ?)`,
			certID, hash, expires.Unix())
		return err
	})
}

// SCEPChallengeExpiry reports whether a challenge (and so a profile) was
// issued for certID, and until when it can be used.
func (s *Store) SCEPChallengeExpiry(ctx context.Context, certID string) (time.Time, bool, error) {
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM scep_challenges WHERE cert_id = ?`, certID).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(expires, 0), true, nil
}

// Enrolment is a SCEP certificate record and its owner's email.
type Enrolment struct {
	Certificate
	Email string
}

// ConsumeSCEPChallenge accepts a challenge for transactionID and moves its
// record from pending to issuing. step-ca retries a webhook with the same
// transaction ID, so a challenge already consumed by the same transaction is
// accepted again while the record is still issuing and the challenge has not
// expired; any other transaction gets ErrChallengeUsed.
func (s *Store) ConsumeSCEPChallenge(ctx context.Context, hash, transactionID string, now time.Time) (*Enrolment, error) {
	var e *Enrolment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var (
			certID   string
			expires  int64
			consumed sql.NullInt64
			usedBy   sql.NullString
		)
		err := tx.QueryRowContext(ctx, `
			SELECT cert_id, expires_at, consumed_at, transaction_id FROM scep_challenges WHERE challenge_hash = ?`, hash).
			Scan(&certID, &expires, &consumed, &usedBy)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case consumed.Valid && usedBy.String != transactionID:
			return ErrChallengeUsed
		case now.Unix() >= expires:
			return ErrChallengeExpired
		case consumed.Valid:
			var status string
			if err := tx.QueryRowContext(ctx, `SELECT status FROM certificates WHERE id = ?`, certID).Scan(&status); err != nil {
				return err
			}
			if status != "issuing" {
				return ErrChallengeUsed
			}
		case !consumed.Valid:
			if _, err := tx.ExecContext(ctx, `UPDATE scep_challenges SET consumed_at = ?, transaction_id = ? WHERE cert_id = ?`,
				now.Unix(), transactionID, certID); err != nil {
				return err
			}
			res, err := tx.ExecContext(ctx, `UPDATE certificates SET status = 'issuing' WHERE id = ? AND status = 'pending'`, certID)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				return errors.Join(ErrNotPending, err)
			}
		}
		e, err = scanEnrolment(tx.QueryRowContext(ctx, enrolmentQuery+` WHERE c.id = ?`, certID))
		return err
	})
	return e, err
}

// EnrolmentByTransaction finds the SCEP record a transaction consumed.
func (s *Store) EnrolmentByTransaction(ctx context.Context, transactionID string) (*Enrolment, error) {
	e, err := scanEnrolment(s.db.QueryRowContext(ctx,
		enrolmentQuery+` JOIN scep_challenges sc ON sc.cert_id = c.id WHERE sc.transaction_id = ?`, transactionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// FailCertificate marks an issuing record failed.
func (s *Store) FailCertificate(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE certificates SET status = 'failed' WHERE id = ? AND status = 'issuing'`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotPending
	}
	return nil
}

const enrolmentQuery = `
	SELECT c.id, c.user_sub, c.device_name, c.method, c.status, COALESCE(c.serial, ''),
	       COALESCE(c.not_before, 0), COALESCE(c.not_after, 0), c.created_at, u.email
	FROM certificates c JOIN users u ON u.sub = c.user_sub`

func scanEnrolment(row interface{ Scan(...any) error }) (*Enrolment, error) {
	var (
		e               Enrolment
		nb, na, created int64
	)
	if err := row.Scan(&e.ID, &e.UserSub, &e.DeviceName, &e.Method, &e.Status, &e.Serial, &nb, &na, &created, &e.Email); err != nil {
		return nil, err
	}
	if nb != 0 {
		e.NotBefore = time.Unix(nb, 0)
	}
	if na != 0 {
		e.NotAfter = time.Unix(na, 0)
	}
	e.CreatedAt = time.Unix(created, 0)
	return &e, nil
}

// CancelSCEPEnrolment deletes userSub's pending Apple enrolment id, its
// device link and its challenge, so a downloaded profile can no longer enrol.
// Once the device has used the challenge the record is issuing, and this returns ErrNotPending:
// the certificate must then be revoked when it is active.
func (s *Store) CancelSCEPEnrolment(ctx context.Context, userSub, id string) (*Certificate, error) {
	var c *Certificate
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		c, err = scanCertificate(tx.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE id = ? AND user_sub = ?`, id, userSub))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if c.Method != "scep" || c.Status != "pending" {
			return ErrNotPending
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM device_links WHERE cert_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scep_challenges WHERE cert_id = ?`, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM certificates WHERE id = ? AND status = 'pending'`, id)
		return err
	})
	return c, err
}

// CancelPendingSCEPEnrolments deletes all of userSub's pending Apple
// enrolments, their device links and their challenges, so no downloaded
// profile or unused link can enrol. Issuing records are kept: step-ca already
// has their CSR, and the NOTIFYING webhook must still record the certificate
// so that it can be revoked.
func (s *Store) CancelPendingSCEPEnrolments(ctx context.Context, userSub string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		const pending = `SELECT id FROM certificates WHERE user_sub = ? AND method = 'scep' AND status = 'pending'`
		if _, err := tx.ExecContext(ctx, `DELETE FROM device_links WHERE cert_id IN (`+pending+`)`, userSub); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scep_challenges WHERE cert_id IN (`+pending+`)`, userSub); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM certificates WHERE user_sub = ? AND method = 'scep' AND status = 'pending'`, userSub)
		return err
	})
}
