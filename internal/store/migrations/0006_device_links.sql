-- One-time short links that serve a pending SCEP record's profile without a
-- session, for devices that cannot sign in (Apple TV). The code is stored
-- only as a SHA-256 hash.
CREATE TABLE device_links (
    cert_id    TEXT PRIMARY KEY REFERENCES certificates(id),
    code_hash  TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
