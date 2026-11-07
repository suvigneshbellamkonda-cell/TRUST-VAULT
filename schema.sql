-- TrustVault database schema.
-- Safe to run more than once: every statement uses IF NOT EXISTS.

-- People who can log in. Accounts are made by an admin, or by the admin
-- registration page (which needs a secret setup code).
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

-- ---- Added on Day 5 (two roles, e-mail and organisation) ----

ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS organisation TEXT;

-- One e-mail address belongs to one account (upper or lower case is the same).
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
    ON users (lower(email)) WHERE email IS NOT NULL;

-- Roles: admin (one, set in the database), owner (uploads and shares) and
-- viewer (sees only what an owner shares). Databases from the "user" period
-- turn every former "user" into an owner.
DO $$
BEGIN
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
    UPDATE users SET role = 'owner' WHERE role = 'user';
    ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'owner', 'viewer'));
END
$$;

-- ---- Added on Day 6 (invitations, password reset, notifications, stars, bin) ----

ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by INTEGER REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS alerts_seen_at TIMESTAMPTZ;

-- Whenever a password hash changes (the app, or someone editing the database
-- by hand to replace the administrator) every session of that user ends.
CREATE OR REPLACE FUNCTION users_bump_session() RETURNS trigger AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
        NEW.session_version := OLD.session_version + 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_bump_session ON users;
CREATE TRIGGER users_bump_session
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION users_bump_session();

-- One row per invitation. Only a hash of the link's secret is stored, so a
-- copy of the database cannot be used to join. A link works once.
CREATE TABLE IF NOT EXISTS invitations (
    id          SERIAL PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('owner', 'viewer')),
    invited_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by     INTEGER REFERENCES users(id)
);

-- One-time codes for "Forgot password". Only a hash of the code is stored.
CREATE TABLE IF NOT EXISTS password_resets (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    otp_hash    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    verified_at TIMESTAMPTZ,
    used_at     TIMESTAMPTZ
);

-- The bell. link is a page inside the app that the notification opens.
CREATE TABLE IF NOT EXISTS notifications (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    message     TEXT NOT NULL,
    link        TEXT NOT NULL,
    document_id INTEGER,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS notifications_by_user ON notifications (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS stars (
    user_id     INTEGER NOT NULL REFERENCES users(id),
    document_id INTEGER NOT NULL REFERENCES documents(id),
    PRIMARY KEY (user_id, document_id)
);

-- Who deleted a document (it stays in the bin for 15 days).
ALTER TABLE documents ADD COLUMN IF NOT EXISTS deleted_by INTEGER;