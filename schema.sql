-- TrustVault database schema.
-- Safe to run more than once: every statement uses IF NOT EXISTS.

-- People who can log in. There is no public sign-up: the admin creates users.
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL,
    password_hash TEXT NOT NULL,          -- never the real password
    role          TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,   -- FALSE = disabled, cannot log in
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Documents. The file itself is stored in the "content" column,
-- so there is no public file URL that could be guessed.
CREATE TABLE IF NOT EXISTS documents (
    id          SERIAL PRIMARY KEY,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    title       TEXT NOT NULL,
    category    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    mime_type   TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    sha256      TEXT NOT NULL,            -- fingerprint of the file content
    content     BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ               -- set when deleted; NULL = not deleted
);

-- Who may access which document. One row per grant.
-- Revoking sets revoked_at instead of deleting the row, so history is kept.
CREATE TABLE IF NOT EXISTS grants (
    id           SERIAL PRIMARY KEY,
    document_id  INTEGER NOT NULL REFERENCES documents(id),
    user_id      INTEGER NOT NULL REFERENCES users(id),
    permission   TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by   INTEGER NOT NULL REFERENCES users(id),
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ,             -- NULL = grant is still active
    revoked_by   INTEGER REFERENCES users(id)
);

-- A user can have at most one ACTIVE grant per document.
CREATE UNIQUE INDEX IF NOT EXISTS one_active_grant_per_user
    ON grants (document_id, user_id)
    WHERE revoked_at IS NULL;