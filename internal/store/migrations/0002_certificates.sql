CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO settings (key, value) VALUES ('cert_limit_default', '5');

-- id is the device UUID; the certificate carries it as urn:authstep:device:<id>.
CREATE TABLE certificates (
    id            TEXT PRIMARY KEY,
    user_sub      TEXT NOT NULL REFERENCES users(sub),
    device_name   TEXT NOT NULL,
    method        TEXT NOT NULL CHECK (method IN ('browser', 'scep')),
    status        TEXT NOT NULL CHECK (status IN ('pending', 'issuing', 'active', 'failed', 'revoked')),
    serial        TEXT UNIQUE,
    not_before    INTEGER,
    not_after     INTEGER,
    revoked_at    INTEGER,
    revoked_by    TEXT,
    revoke_reason TEXT,
    created_at    INTEGER NOT NULL
);

CREATE INDEX certificates_user_sub ON certificates(user_sub);
