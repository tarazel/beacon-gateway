-- Clip cache retention. The gateway caches remuxed clips under data/clips/<id>.mp4.
-- A background pruner deletes cached clips for events older than clip_retention_days
-- (default 30), unless the event is pinned via events.keep_clip. A value <= 0 disables
-- automatic pruning.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO settings (key, value) VALUES ('clip_retention_days', '30');

-- Pin a clip to exclude it (and its cached file) from automatic cleanup.
ALTER TABLE events ADD COLUMN keep_clip INTEGER NOT NULL DEFAULT 0;
