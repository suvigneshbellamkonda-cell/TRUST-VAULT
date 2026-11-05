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

-- ---- Added on Day 2 (login) ----

-- Bumped whenever a user logs out or is disabled. A login cookie carries the
-- number it was issued with, so bumping it kills every cookie issued before.
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;

-- Every login attempt, good or bad. Used to lock out password guessing.
CREATE TABLE IF NOT EXISTS login_attempts (
    id           SERIAL PRIMARY KEY,
    username     TEXT NOT NULL,
    ip           TEXT NOT NULL,
    success      BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS login_attempts_by_user ON login_attempts (username, attempted_at);
CREATE INDEX IF NOT EXISTS login_attempts_by_ip ON login_attempts (ip, attempted_at); 

-- ---- Added on Day 3 (documents and audit log) ----

CREATE INDEX IF NOT EXISTS documents_by_owner ON documents (owner_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS grants_by_user ON grants (user_id) WHERE revoked_at IS NULL;

-- The audit trail. Rows are only ever added. Each row stores a hash of the
-- row before it, so removing or changing an old row breaks the chain.
-- document_id and target_user_id have no foreign key on purpose: attempts on
-- ids that do not exist must still be recorded.
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL PRIMARY KEY,
    at             TIMESTAMPTZ NOT NULL,
    actor_id       INTEGER,
    actor_username TEXT,
    action         TEXT NOT NULL,
    document_id    INTEGER,
    target_user_id INTEGER,
    outcome        TEXT NOT NULL CHECK (outcome IN ('ok', 'denied')),
    detail         TEXT,
    ip             TEXT,
    prev_hash      TEXT NOT NULL,
    row_hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_log_by_document ON audit_log (document_id);

-- Refuse to change or remove audit rows, even from the application itself.
CREATE OR REPLACE FUNCTION audit_log_refuse_changes() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log;
CREATE TRIGGER audit_log_no_change
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_changes();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse_changes();