// Package store persists AuthStep state in SQLite.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

// Open opens the database at path and applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer at a time; a single connection serializes
	// writes in Go instead of failing with SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	var current int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}

	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		name := strings.TrimPrefix(f, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", name)
		}
		if version <= current {
			continue
		}
		body, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		if err := s.inTx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, version)
			return err
		}); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

type User struct {
	Sub         string
	Email       string
	Name        string
	IsAdmin     bool
	LastLoginAt time.Time
}

// UpsertUser records a login. cert_limit_override is left unchanged.
func (s *Store) UpsertUser(ctx context.Context, u User) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (sub, email, name, is_admin, last_login_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (sub) DO UPDATE SET
			email = excluded.email, name = excluded.name,
			is_admin = excluded.is_admin, last_login_at = excluded.last_login_at`,
		u.Sub, u.Email, u.Name, u.IsAdmin, u.LastLoginAt.Unix())
	return err
}

type Session struct {
	IDHash     string
	User       User
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, idHash, userSub, csrfToken string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id_hash, user_sub, csrf_token, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)`,
		idHash, userSub, csrfToken, now.Unix(), now.Unix())
	return err
}

func (s *Store) SessionByHash(ctx context.Context, idHash string) (*Session, error) {
	var (
		sess                         Session
		created, lastSeen, lastLogin int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id_hash, s.csrf_token, s.created_at, s.last_seen_at,
		       u.sub, u.email, u.name, u.is_admin, u.last_login_at
		FROM sessions s JOIN users u ON u.sub = s.user_sub
		WHERE s.id_hash = ?`, idHash).Scan(
		&sess.IDHash, &sess.CSRFToken, &created, &lastSeen,
		&sess.User.Sub, &sess.User.Email, &sess.User.Name, &sess.User.IsAdmin, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt = time.Unix(created, 0)
	sess.LastSeenAt = time.Unix(lastSeen, 0)
	sess.User.LastLoginAt = time.Unix(lastLogin, 0)
	return &sess, nil
}

func (s *Store) TouchSession(ctx context.Context, idHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, now.Unix(), idHash)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteExpiredSessions removes sessions idle since before idleBefore or
// created before createdBefore.
func (s *Store) DeleteExpiredSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE last_seen_at < ? OR created_at < ?`,
		idleBefore.Unix(), createdBefore.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
