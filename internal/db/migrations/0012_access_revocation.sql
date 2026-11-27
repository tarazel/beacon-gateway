-- Revoking access must outlive the allowlist entry: a known identity is never
-- re-checked against the allowlist, so revocation is recorded explicitly.
--
-- users.disabled_at: set = the account can't sign in, refresh, or use a token it
-- already holds. revoked_emails: blocks an email that has no account yet (for
-- example one listed in APPLE_ALLOWED_EMAILS). `beacon-admin allow` clears both.
ALTER TABLE users ADD COLUMN disabled_at INTEGER;

CREATE TABLE revoked_emails (
    email      TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);
