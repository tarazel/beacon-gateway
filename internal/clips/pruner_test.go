package clips

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type meta struct {
	keep  bool
	start time.Time
	found bool
}

func writeFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func newTestPruner(dir string, now time.Time, days int, m map[string]meta) *Pruner {
	p := NewPruner(dir, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(ctx context.Context) (int, error) { return days, nil },
		func(ctx context.Context, id string) (bool, time.Time, bool, error) {
			v, ok := m[id]
			if !ok {
				return false, time.Time{}, false, nil
			}
			return v.keep, v.start, v.found, nil
		},
	)
	p.now = func() time.Time { return now }
	return p
}

func TestPruneOnce(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

	writeFile(t, dir, "old.mp4")    // event 87 days old, not pinned -> removed
	writeFile(t, dir, "recent.mp4") // event 7 days old -> kept
	writeFile(t, dir, "pinned.mp4") // event old but pinned -> kept
	orphan := writeFile(t, dir, "orphan.mp4")
	keepTxt := writeFile(t, dir, "notes.txt") // not an mp4 -> ignored

	// Orphan (no event row) ages by file modtime; set it well past the cutoff.
	oldMod := now.Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(orphan, oldMod, oldMod); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	m := map[string]meta{
		"old":    {found: true, start: now.Add(-87 * 24 * time.Hour)},
		"recent": {found: true, start: now.Add(-7 * 24 * time.Hour)},
		"pinned": {found: true, keep: true, start: now.Add(-200 * 24 * time.Hour)},
	}

	p := newTestPruner(dir, now, 30, m)
	removed, err := p.PruneOnce(context.Background())
	if err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (old + orphan)", removed)
	}

	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	if exists("old.mp4") {
		t.Error("old.mp4 should have been pruned")
	}
	if exists("orphan.mp4") {
		t.Error("orphan.mp4 should have been pruned (aged by modtime)")
	}
	if !exists("recent.mp4") {
		t.Error("recent.mp4 should have been kept")
	}
	if !exists("pinned.mp4") {
		t.Error("pinned.mp4 should have been kept (pinned)")
	}
	if !exists("notes.txt") || keepTxt == "" {
		t.Error("non-mp4 files must be left alone")
	}
}

func TestPruneOnceDisabled(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	writeFile(t, dir, "old.mp4")

	m := map[string]meta{"old": {found: true, start: now.Add(-200 * 24 * time.Hour)}}
	p := newTestPruner(dir, now, 0, m) // 0 == disabled

	removed, err := p.PruneOnce(context.Background())
	if err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0 when disabled", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.mp4")); err != nil {
		t.Error("old.mp4 must survive when pruning is disabled")
	}
}

func TestPruneOnceMissingDir(t *testing.T) {
	p := newTestPruner(filepath.Join(t.TempDir(), "nope"), time.Now(), 30, nil)
	removed, err := p.PruneOnce(context.Background())
	if err != nil {
		t.Fatalf("PruneOnce on missing dir should be a no-op, got %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}
