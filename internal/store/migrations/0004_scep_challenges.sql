-- One challenge per SCEP certificate record. The challenge itself is stored
-- only as a SHA-256 hash.
CREATE TABLE scep_challenges (
    cert_id        TEXT PRIMARY KEY REFERENCES certificates(id),
    challenge_hash TEXT NOT NULL UNIQUE,
    expires_at     INTEGER NOT NULL,
    consumed_at    INTEGER,
    transaction_id TEXT UNIQUE
);
