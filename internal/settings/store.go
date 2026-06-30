// Package settings is a tiny key/value store over the SQLite `settings` table,
// used for gateway-wide (not per-user) configuration that the iOS app can change
// at runtime — currently just the clip cache retention window.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
)

// Setting keys.
const KeyClipRetentionDays = "clip_retention_days"

// KeyRelayInstanceToken stores the opaque instance token the gateway receives
// when it registers with the central push relay on first boot.
const KeyRelayInstanceToken = "relay_instance_token"

// DefaultClipRetentionDays is the seeded default and the fallback used when the
// row is missing or unparseable.
const DefaultClipRetentionDays = 30

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// GetInt returns the integer value for key, or def if the key is absent or the
// stored value isn't a valid integer.
func (s *Store) GetInt(ctx context.Context, key string, def int) (int, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, nil
	}
	return n, nil
}

// SetInt upserts the integer value for key.
func (s *Store) SetInt(ctx context.Context, key string, val int) error {
	return s.SetString(ctx, key, strconv.Itoa(val))
}

// GetString returns the value for key, or def if the key is absent.
func (s *Store) GetString(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	return v, nil
}

// SetString upserts the value for key.
func (s *Store) SetString(ctx context.Context, key, val string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, val)
	return err
}
