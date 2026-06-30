-- Family multi-user: per-user role + per-camera access scope.
--
-- role: 'admin' manages users/cameras/settings and sees every camera; 'member'
-- is a regular family user. New users default to 'member'; the gateway promotes
-- the first-ever user (and any ADMIN_EMAILS) to 'admin' at sign-in.
--
-- user_cameras scopes a member to specific cameras. The rule (enforced in the API
-- and the push dispatcher): an admin sees all cameras; a member with ZERO rows
-- here sees all cameras (the friendly household default); a member with any rows
-- sees exactly those cameras. Rows reference camera ids from CAMERAS_JSON.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';

CREATE TABLE user_cameras (
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    camera   TEXT NOT NULL,
    PRIMARY KEY (user_id, camera)
);
