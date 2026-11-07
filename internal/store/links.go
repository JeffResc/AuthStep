package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrLinkExists  = errors.New("a device link was already created for this certificate")
	ErrLinkExpired = errors.New("device link expired")
	ErrLinkUsed    = errors.New("device link already used")
)

// CreateDeviceLink stores the hash of the one device link a pending SCEP
// record can get. It fails if the record has a link or its profile was
// already downloaded.
func (s *Store) CreateDeviceLink(ctx context.Context, certID, hash string, expires time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var links, challenges int
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM device_links WHERE cert_id = ?),
			(SELECT COUNT(*) FROM scep_challenges WHERE cert_id = ?)`, certID, certID).Scan(&links, &challenges); err != nil {
			return err
		}
		if links != 0 {
			return ErrLinkExists
		}
		if challenges != 0 {
			return ErrChallengeExists
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO device_links (cert_id, code_hash, expires_at) VALUES (?, ?, ?)`,
			certID, hash, expires.Unix())
		return err
	})
}

// UseDeviceLink marks the link with hash used and returns its record, which
// must still be pending.
func (s *Store) UseDeviceLink(ctx context.Context, hash string, now time.Time) (*Enrolment, error) {
	var e *Enrolment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var (
			certID  string
			expires int64
			used    sql.NullInt64
		)
		err := tx.QueryRowContext(ctx, `SELECT cert_id, expires_at, used_at FROM device_links WHERE code_hash = ?`, hash).
			Scan(&certID, &expires, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if used.Valid {
			return ErrLinkUsed
		}
		if now.Unix() >= expires {
			return ErrLinkExpired
		}
		e, err = scanEnrolment(tx.QueryRowContext(ctx, enrolmentQuery+` WHERE c.id = ?`, certID))
		if err != nil {
			return err
		}
		if e.Method != "scep" || e.Status != "pending" {
			return ErrNotPending
		}
		_, err = tx.ExecContext(ctx, `UPDATE device_links SET used_at = ? WHERE cert_id = ?`, now.Unix(), certID)
		return err
	})
	return e, err
}

// DeviceLinkExpiry reports whether an unused device link exists for certID,
// and until when it can be used.
func (s *Store) DeviceLinkExpiry(ctx context.Context, certID string) (time.Time, bool, error) {
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM device_links WHERE cert_id = ? AND used_at IS NULL`, certID).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(expires, 0), true, nil
}
