-- Per-user server-side notification rules — applied in the push dispatcher AFTER
-- scope + mute, BEFORE delivery. Each family member tunes their own alerts
-- (e.g. dad drops 'car', a kid gets nothing after 21:00). One row per user; an
-- absent row = notify for everything (the friendly default). Rules apply across
-- all of that user's cameras (per-camera overrides are a future extension).
--
--   labels: JSON array. Empty = no filter. Notify only when the event's label is in the set.
--   zones:  JSON array. Empty = no filter. Notify only when the event touches a zone in the set.
--   min_score: notify only when the event's top_score >= this (0 = any).
--   cooldown_seconds: after notifying a user for a camera, suppress further pushes
--     to that user for that camera for this many seconds (0 = no cooldown).
--   quiet_start_min / quiet_end_min: minutes from LOCAL midnight in [0,1440) marking
--     a quiet window in which pushes are suppressed; -1/-1 = disabled. The window may
--     wrap past midnight (e.g. 1320..420 = 22:00..07:00). Evaluated in the gateway's
--     local time — for a household-in-one-timezone product that is the family's time.
CREATE TABLE notification_rules (
    user_id          TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    labels           TEXT NOT NULL DEFAULT '',
    zones            TEXT NOT NULL DEFAULT '',
    min_score        REAL NOT NULL DEFAULT 0,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
    quiet_start_min  INTEGER NOT NULL DEFAULT -1,
    quiet_end_min    INTEGER NOT NULL DEFAULT -1,
    updated_at       INTEGER NOT NULL DEFAULT 0
);

-- Cooldown bookkeeping: the last time we decided to notify (user, camera). Kept
-- separate from notification_rules so it can churn without touching user settings.
CREATE TABLE notification_cooldowns (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    camera    TEXT NOT NULL,
    last_sent INTEGER NOT NULL,
    PRIMARY KEY (user_id, camera)
);
