-- Per-camera alert mute, complementing the global per-user mute in users.muted_until.
-- While a (user, camera) row's muted_until (unix seconds) is in the future, the push
-- dispatcher skips that user's devices for events from that camera. Rows are deleted
-- when a mute is cleared.
CREATE TABLE camera_mutes (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    camera      TEXT NOT NULL,
    muted_until INTEGER NOT NULL,
    PRIMARY KEY (user_id, camera)
);
