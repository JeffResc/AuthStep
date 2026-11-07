-- Emails waiting to be sent. A background worker sends them and retries
-- failures, so a slow or broken SMTP server never blocks or undoes an action.
CREATE TABLE outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient       TEXT NOT NULL,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER,          -- NULL once sent or given up
    sent_at         INTEGER,
    last_error      TEXT
);

CREATE INDEX outbox_due ON outbox(next_attempt_at);

-- Expiry reminders already handled, so each threshold is emailed once.
CREATE TABLE notifications_sent (
    cert_id        TEXT NOT NULL REFERENCES certificates(id),
    threshold_days INTEGER NOT NULL,
    sent_at        INTEGER NOT NULL,
    PRIMARY KEY (cert_id, threshold_days)
);
