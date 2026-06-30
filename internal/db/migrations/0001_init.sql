CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    apple_sub    TEXT UNIQUE NOT NULL,
    email        TEXT,
    name         TEXT,
    created_at   INTEGER NOT NULL
);

CREATE TABLE devices (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    apns_token    TEXT NOT NULL UNIQUE,
    platform      TEXT NOT NULL DEFAULT 'ios',
    app_version   TEXT,
    last_seen_at  INTEGER NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE INDEX idx_devices_user ON devices(user_id);

CREATE TABLE events (
    id            TEXT PRIMARY KEY,
    camera        TEXT NOT NULL,
    label         TEXT NOT NULL,
    sub_label     TEXT,
    start_time    INTEGER NOT NULL,
    end_time      INTEGER,
    top_score     REAL,
    has_snapshot  INTEGER NOT NULL DEFAULT 0,
    has_clip      INTEGER NOT NULL DEFAULT 0,
    zones         TEXT,
    raw_json      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE INDEX idx_events_camera_start ON events(camera, start_time DESC);
CREATE INDEX idx_events_start ON events(start_time DESC);
CREATE INDEX idx_events_label ON events(label, start_time DESC);

CREATE TABLE refresh_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    device_id    TEXT REFERENCES devices(id) ON DELETE SET NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    created_at   INTEGER NOT NULL
);

CREATE INDEX idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_expires ON refresh_tokens(expires_at);
