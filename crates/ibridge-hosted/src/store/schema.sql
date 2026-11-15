CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    apple_id TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE grants (
    id BLOB NOT NULL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts (id),
    kind TEXT NOT NULL,
    name TEXT,
    scope TEXT NOT NULL,
    status TEXT NOT NULL,
    failure_count INTEGER NOT NULL DEFAULT 0,
    first_failure_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE seals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id BLOB NOT NULL REFERENCES grants (id),
    purpose TEXT NOT NULL,
    lookup BLOB NOT NULL UNIQUE,
    nonce BLOB,
    ciphertext BLOB,
    expires_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX seals_by_grant ON seals (grant_id);
