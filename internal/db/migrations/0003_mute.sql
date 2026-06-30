-- Per-user "mute alerts" support. While muted_until (unix seconds) is in the
-- future, the push dispatcher skips that user's devices. NULL = not muted.
ALTER TABLE users ADD COLUMN muted_until INTEGER;
