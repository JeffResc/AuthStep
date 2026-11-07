CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    actor_sub   TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    ip          TEXT NOT NULL,
    details     TEXT NOT NULL
);

CREATE INDEX audit_log_ts ON audit_log(ts);
