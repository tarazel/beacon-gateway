-- Invite codes: how an admin onboards a family member without knowing their
-- Apple relay email up front. An admin mints a code (with a role + optional
-- camera scope); the invitee enters it on first Sign in with Apple, which creates
-- their account with that role/scope and consumes the invite (single-use).
--
-- cameras: JSON array of camera ids to scope the new member to; NULL/empty = all.
-- A valid invite has consumed_at IS NULL AND (expires_at IS NULL OR expires_at > now).
CREATE TABLE invites (
    code         TEXT PRIMARY KEY,
    role         TEXT NOT NULL DEFAULT 'member',
    cameras      TEXT,
    note         TEXT,
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    consumed_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    consumed_at  INTEGER
);
