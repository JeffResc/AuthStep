package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrLimitReached = errors.New("certificate limit reached")
	ErrNotPending   = errors.New("certificate is not pending")
	ErrNotActive    = errors.New("certificate is not active")
)

type Certificate struct {
	ID         string
	UserSub    string
	DeviceName string
	Method     string
	Status     string
	Serial     string
	NotBefore  time.Time
	NotAfter   time.Time
	CreatedAt  time.Time
}

// Expired reports whether an active certificate is past its validity.
func (c *Certificate) Expired(now time.Time) bool {
	return c.Status == "active" && !c.NotAfter.After(now)
}

// ReserveCertificate creates a pending certificate record unless the user is
// at their limit. Active certificates that have not expired and pending
// records created after pendingSince count toward the limit.
func (s *Store) ReserveCertificate(ctx context.Context, c Certificate, now, pendingSince time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var limit int
		err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(u.cert_limit_override, CAST(s.value AS INTEGER))
			FROM users u, settings s
			WHERE u.sub = ? AND s.key = 'cert_limit_default'`, c.UserSub).Scan(&limit)
		if err != nil {
			return err
		}
		var used int
		err = tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM certificates
			WHERE user_sub = ? AND (
				(status = 'active' AND not_after > ?) OR
				(status IN ('pending', 'issuing') AND created_at > ?))`,
			c.UserSub, now.Unix(), pendingSince.Unix()).Scan(&used)
		if err != nil {
			return err
		}
		if used >= limit {
			return ErrLimitReached
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO certificates (id, user_sub, device_name, method, status, created_at)
			VALUES (?, ?, ?, ?, 'pending', ?)`,
			c.ID, c.UserSub, c.DeviceName, c.Method, now.Unix())
		return err
	})
}

// UserCertificate returns the certificate with id if it belongs to userSub.
func (s *Store) UserCertificate(ctx context.Context, userSub, id string) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE id = ? AND user_sub = ?`, id, userSub)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListUserCertificates returns userSub's certificates, newest first.
func (s *Store) ListUserCertificates(ctx context.Context, userSub string) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE user_sub = ? ORDER BY created_at DESC, id`, userSub)
	if err != nil {
		return nil, err
	}
	// rows.Err below reports iteration errors; Close cannot add to them.
	defer func() { _ = rows.Close() }()
	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ActivateCertificate records the issued certificate on a pending (browser)
// or issuing (SCEP) record.
func (s *Store) ActivateCertificate(ctx context.Context, id, serial string, notBefore, notAfter time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE certificates SET status = 'active', serial = ?, not_before = ?, not_after = ?
		WHERE id = ? AND status IN ('pending', 'issuing')`,
		serial, notBefore.Unix(), notAfter.Unix(), id)
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

const certColumns = `id, user_sub, device_name, method, status, COALESCE(serial, ''), COALESCE(not_before, 0), COALESCE(not_after, 0), created_at`

func scanCertificate(row interface{ Scan(...any) error }) (*Certificate, error) {
	var (
		c               Certificate
		nb, na, created int64
	)
	if err := row.Scan(&c.ID, &c.UserSub, &c.DeviceName, &c.Method, &c.Status, &c.Serial, &nb, &na, &created); err != nil {
		return nil, err
	}
	if nb != 0 {
		c.NotBefore = time.Unix(nb, 0)
	}
	if na != 0 {
		c.NotAfter = time.Unix(na, 0)
	}
	c.CreatedAt = time.Unix(created, 0)
	return &c, nil
}

// CertificateByID returns any user's certificate. Callers check authorization.
func (s *Store) CertificateByID(ctx context.Context, id string) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE id = ?`, id)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// RevokeCertificate marks an active certificate revoked.
func (s *Store) RevokeCertificate(ctx context.Context, id, revokedBy, reason string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE certificates SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoke_reason = ?
		WHERE id = ? AND status = 'active'`,
		at.Unix(), revokedBy, reason, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotActive
	}
	return nil
}
