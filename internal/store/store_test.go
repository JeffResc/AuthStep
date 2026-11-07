package store

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, path
}

func TestMigrationsAreIdempotent(t *testing.T) {
	_, path := openTest(t)
	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() {
		if err := s2.Close(); err != nil {
			t.Error(err)
		}
	})
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(files) {
		t.Fatalf("schema_migrations rows = %d, want %d", n, len(files))
	}
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Unix(1_800_000_000, 0)

	u := User{Sub: "sub-1", Email: "a@example.com", Name: "A", LastLoginAt: now}
	if err := s.UpsertUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u.IsAdmin, u.Email = true, "a2@example.com"
	if err := s.UpsertUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "h1", "sub-1", "csrf-1", now); err != nil {
		t.Fatal(err)
	}

	got, err := s.SessionByHash(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.User.Email != "a2@example.com" || !got.User.IsAdmin || got.CSRFToken != "csrf-1" || !got.CreatedAt.Equal(now) {
		t.Fatalf("unexpected session: %+v", got)
	}

	later := now.Add(time.Hour)
	if err := s.TouchSession(ctx, "h1", later); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SessionByHash(ctx, "h1"); !got.LastSeenAt.Equal(later) {
		t.Fatalf("last_seen_at = %v, want %v", got.LastSeenAt, later)
	}

	// Not idle, but created too long ago.
	n, err := s.DeleteExpiredSessions(ctx, now, later)
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpiredSessions = %d, %v; want 1", n, err)
	}
	if _, err := s.SessionByHash(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: err = %v, want ErrNotFound", err)
	}
}

func TestSessionRequiresUser(t *testing.T) {
	s, _ := openTest(t)
	if err := s.CreateSession(context.Background(), "h", "missing", "c", time.Now()); err == nil {
		t.Fatal("session for unknown user was accepted; foreign keys are not enforced")
	}
}
