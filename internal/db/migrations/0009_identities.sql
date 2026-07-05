-- Multi-provider identity: a user can sign in with Apple OR Google, and the same
-- person (matched on verified email) is one account across both. Historically the
-- users table pinned identity to a single apple_sub column; this table generalizes
-- that to (provider, provider_sub) → user, so a user may have more than one linked
-- identity (e.g. Apple on their iPhone + Google on their Samsung).
--
-- This migration is purely additive — it does NOT rebuild or alter the users table
-- (rebuilding it with foreign_keys ON would implicitly cascade-delete devices and
-- refresh tokens). The legacy users.apple_sub column stays as-is; it remains a
-- NOT NULL UNIQUE anchor filled with the real Apple sub for Apple users or a
-- synthetic "google:<sub>" value for Google-only users (mirroring the existing
-- "dev:<email>" convention used by beacon-admin create-user). user_identities is
-- the authoritative map used for all sign-in lookups going forward.
CREATE TABLE user_identities (
    provider     TEXT NOT NULL,          -- 'apple' | 'google'
    provider_sub TEXT NOT NULL,          -- the identity provider's stable subject id
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email        TEXT,                   -- email as asserted by this provider (may differ per provider)
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (provider, provider_sub)
);

CREATE INDEX idx_identities_user ON user_identities(user_id);

-- Backfill every existing user's Apple identity so provider lookups find them.
INSERT INTO user_identities (provider, provider_sub, user_id, email, created_at)
SELECT 'apple', apple_sub, id, email, created_at FROM users;
