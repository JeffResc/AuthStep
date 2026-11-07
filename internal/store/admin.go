package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

var ErrInvalidLimit = errors.New("limit must be between 0 and 1000")

const maxLimit = 1000

// UserSummary is a user with their effective certificate limit and usage.
type UserSummary struct {
	User
	LimitOverride *int
	Limit         int
	ActiveCerts   int
}

// ListUsers returns all users who have signed in, ordered by email.
func (s *Store) ListUsers(ctx context.Context, now time.Time) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx, userSummaryQuery+` ORDER BY u.email, u.sub`, now.Unix())
	if err != nil {
		return nil, err
	}
	// rows.Err below reports iteration errors; Close cannot add to them.
	defer func() { _ = rows.Close() }()
	var out []UserSummary
	for rows.Next() {
		u, err := scanUserSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) UserSummary(ctx context.Context, sub string, now time.Time) (*UserSummary, error) {
	u, err := scanUserSummary(s.db.QueryRowContext(ctx, userSummaryQuery+` AND u.sub = ?`, now.Unix(), sub))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

const userSummaryQuery = `
	SELECT u.sub, u.email, u.name, u.is_admin, u.last_login_at, u.cert_limit_override,
	       COALESCE(u.cert_limit_override, CAST(s.value AS INTEGER)),
	       (SELECT COUNT(*) FROM certificates c WHERE c.user_sub = u.sub AND c.status = 'active' AND c.not_after > ?1)
	FROM users u, settings s
	WHERE s.key = 'cert_limit_default'`

func scanUserSummary(row interface{ Scan(...any) error }) (*UserSummary, error) {
	var (
		u         UserSummary
		lastLogin int64
		override  sql.NullInt64
	)
	if err := row.Scan(&u.Sub, &u.Email, &u.Name, &u.IsAdmin, &lastLogin, &override, &u.Limit, &u.ActiveCerts); err != nil {
		return nil, err
	}
	u.LastLoginAt = time.Unix(lastLogin, 0)
	if override.Valid {
		v := int(override.Int64)
		u.LimitOverride = &v
	}
	return &u, nil
}

func (s *Store) DefaultCertLimit(ctx context.Context) (int, error) {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'cert_limit_default'`).Scan(&v); err != nil {
		return 0, err
	}
	return strconv.Atoi(v)
}

func (s *Store) SetDefaultCertLimit(ctx context.Context, limit int) error {
	if limit < 0 || limit > maxLimit {
		return ErrInvalidLimit
	}
	_, err := s.db.ExecContext(ctx, `UPDATE settings SET value = ? WHERE key = 'cert_limit_default'`, strconv.Itoa(limit))
	return err
}

// SetUserCertLimit sets a per-user override; nil restores the default.
func (s *Store) SetUserCertLimit(ctx context.Context, sub string, limit *int) error {
	if limit != nil && (*limit < 0 || *limit > maxLimit) {
		return ErrInvalidLimit
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET cert_limit_override = ? WHERE sub = ?`, limit, sub)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

type AuditEntry struct {
	ID         int64
	Time       time.Time
	ActorSub   string
	ActorEmail string
	Action     string
	Target     string
	IP         string
	Details    map[string]any
}

func (s *Store) InsertAuditEntry(ctx context.Context, e AuditEntry) error {
	details, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, actor_sub, actor_email, action, target, ip, details) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Time.Unix(), e.ActorSub, e.ActorEmail, e.Action, e.Target, e.IP, string(details))
	return err
}

// ListAuditEntries returns the newest entries first.
func (s *Store) ListAuditEntries(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, actor_sub, actor_email, action, target, ip, details
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	// rows.Err below reports iteration errors; Close cannot add to them.
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var (
			e       AuditEntry
			ts      int64
			details string
		)
		if err := rows.Scan(&e.ID, &ts, &e.ActorSub, &e.ActorEmail, &e.Action, &e.Target, &e.IP, &details); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		if err := json.Unmarshal([]byte(details), &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
