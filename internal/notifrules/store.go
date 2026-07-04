package notifrules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Store persists per-user rules and cooldown state, and implements the decision
// used by the push dispatcher. It satisfies the apns.Ruler interface (via an
// adapter in cmd/gateway, to keep the packages decoupled).
type Store struct {
	db  *sql.DB
	now func() time.Time
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// Get returns the user's stored rule, or DefaultRule (allow-all) when none exists.
func (s *Store) Get(ctx context.Context, userID string) (Rule, error) {
	r := DefaultRule()
	var labels, zones string
	err := s.db.QueryRowContext(ctx,
		`SELECT labels, zones, min_score, cooldown_seconds, quiet_start_min, quiet_end_min
		 FROM notification_rules WHERE user_id = ?`, userID).
		Scan(&labels, &zones, &r.MinScore, &r.CooldownSeconds, &r.QuietStartMin, &r.QuietEndMin)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultRule(), nil
	}
	if err != nil {
		return Rule{}, err
	}
	r.Labels = parseArray(labels)
	r.Zones = parseArray(zones)
	return r, nil
}

// Set upserts the user's rule, normalizing/clamping the inputs first.
func (s *Store) Set(ctx context.Context, userID string, r Rule) error {
	r = r.normalized()
	labels, _ := json.Marshal(r.Labels)
	zones, _ := json.Marshal(r.Zones)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_rules
			(user_id, labels, zones, min_score, cooldown_seconds, quiet_start_min, quiet_end_min, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			labels=excluded.labels, zones=excluded.zones, min_score=excluded.min_score,
			cooldown_seconds=excluded.cooldown_seconds, quiet_start_min=excluded.quiet_start_min,
			quiet_end_min=excluded.quiet_end_min, updated_at=excluded.updated_at`,
		userID, string(labels), string(zones), r.MinScore, r.CooldownSeconds,
		r.QuietStartMin, r.QuietEndMin, s.now().Unix())
	return err
}

// Allows reports whether userID should be notified for ev, applying that user's
// stored rule. It ALSO records the notification time for cooldown when the user
// passes, so it must be called exactly once per (user, event) at decision time.
// It fails OPEN: a storage error never silently drops a push.
func (s *Store) Allows(ctx context.Context, userID string, ev Event) bool {
	rule, err := s.Get(ctx, userID)
	if err != nil {
		return true // fail open — don't drop a family's pushes on a rules read error
	}
	now := s.now()
	if !rule.staticAllows(ev, now) {
		return false
	}
	if rule.CooldownSeconds > 0 {
		return s.touchCooldown(ctx, userID, ev.Camera, rule.CooldownSeconds, now)
	}
	return true
}

// touchCooldown returns true (and records now) when the (user, camera) is outside
// its cooldown window, false when still cooling down. Fails open on error.
func (s *Store) touchCooldown(ctx context.Context, userID, camera string, seconds int, now time.Time) bool {
	var last int64
	err := s.db.QueryRowContext(ctx,
		`SELECT last_sent FROM notification_cooldowns WHERE user_id = ? AND camera = ?`,
		userID, camera).Scan(&last)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// never notified for this camera — allow and record
	case err != nil:
		return true // fail open
	default:
		if now.Unix()-last < int64(seconds) {
			return false // still cooling down
		}
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_cooldowns (user_id, camera, last_sent) VALUES (?, ?, ?)
		ON CONFLICT(user_id, camera) DO UPDATE SET last_sent = excluded.last_sent`,
		userID, camera, now.Unix()); err != nil {
		return true // fail open — we've decided to notify
	}
	return true
}

// normalized trims/dedupes label & zone sets and clamps numeric fields to their
// valid ranges, so bad API input can't produce a nonsensical stored rule.
func (r Rule) normalized() Rule {
	r.Labels = cleanSet(r.Labels)
	r.Zones = cleanSet(r.Zones)
	if r.MinScore < 0 {
		r.MinScore = 0
	}
	if r.MinScore > 1 {
		r.MinScore = 1
	}
	if r.CooldownSeconds < 0 {
		r.CooldownSeconds = 0
	}
	r.QuietStartMin = clampMinute(r.QuietStartMin)
	r.QuietEndMin = clampMinute(r.QuietEndMin)
	// Quiet hours are all-or-nothing: if either bound is disabled, disable both.
	if r.QuietStartMin < 0 || r.QuietEndMin < 0 {
		r.QuietStartMin, r.QuietEndMin = -1, -1
	}
	return r
}

// clampMinute keeps a minutes-from-midnight value in [-1, 1439]; anything <0 is -1 (disabled).
func clampMinute(m int) int {
	if m < 0 {
		return -1
	}
	if m > 1439 {
		return 1439
	}
	return m
}

func cleanSet(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func parseArray(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
