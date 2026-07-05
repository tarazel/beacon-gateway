package notifrules

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tarazel/beacon-gateway/internal/db"
)

func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	// notification_rules / cooldowns FK-reference users, and FKs are enforced.
	if _, err := d.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, role, created_at) VALUES ('u1', 'sub-u1', 'member', 0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return NewStore(d), ctx
}

func TestGetDefaultWhenNoRow(t *testing.T) {
	s, ctx := newTestStore(t)
	r, err := s.Get(ctx, "u1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(r.Labels) != 0 || r.MinScore != 0 || r.QuietStartMin != -1 {
		t.Fatalf("expected DefaultRule, got %+v", r)
	}
}

func TestSetGetRoundtrip(t *testing.T) {
	s, ctx := newTestStore(t)
	in := Rule{Labels: []string{"person", "car"}, Zones: []string{"driveway"}, MinScore: 0.6, CooldownSeconds: 120, QuietStartMin: 1320, QuietEndMin: 420}
	if err := s.Set(ctx, "u1", in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "u1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Labels) != 2 || got.Labels[0] != "person" || got.Zones[0] != "driveway" ||
		got.MinScore != 0.6 || got.CooldownSeconds != 120 || got.QuietStartMin != 1320 || got.QuietEndMin != 420 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestAllows_LabelFilterAndCooldown(t *testing.T) {
	s, ctx := newTestStore(t)
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }

	// person allowed, car dropped; 60s cooldown per camera.
	if err := s.Set(ctx, "u1", Rule{Labels: []string{"person"}, CooldownSeconds: 60, QuietStartMin: -1, QuietEndMin: -1}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if s.Allows(ctx, "u1", Event{Camera: "front", Label: "car"}) {
		t.Error("car should be filtered by label allowlist")
	}
	if !s.Allows(ctx, "u1", Event{Camera: "front", Label: "person"}) {
		t.Error("first person event should notify")
	}
	// Same camera, 30s later — still cooling down.
	s.now = func() time.Time { return base.Add(30 * time.Second) }
	if s.Allows(ctx, "u1", Event{Camera: "front", Label: "person"}) {
		t.Error("second person event within cooldown should be suppressed")
	}
	// A different camera is tracked independently — not cooling down.
	if !s.Allows(ctx, "u1", Event{Camera: "back", Label: "person"}) {
		t.Error("other camera should not be affected by front's cooldown")
	}
	// 61s after the first — cooldown elapsed.
	s.now = func() time.Time { return base.Add(61 * time.Second) }
	if !s.Allows(ctx, "u1", Event{Camera: "front", Label: "person"}) {
		t.Error("event after cooldown window should notify again")
	}
}
