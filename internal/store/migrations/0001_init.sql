CREATE TABLE users (
    sub                 TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    name                TEXT NOT NULL,
    is_admin            INTEGER NOT NULL,
    cert_limit_override INTEGER,
    last_login_at       INTEGER NOT NULL
);

-- id_hash is SHA-256 of the session cookie value, so a copy of the database
-- does not hold usable session cookies.
CREATE TABLE sessions (
    id_hash      TEXT PRIMARY KEY,
    user_sub     TEXT NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);

CREATE INDEX sessions_user_sub ON sessions(user_sub);
