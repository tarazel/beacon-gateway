package settings_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tarazel/beacon-gateway/internal/db"
	"github.com/tarazel/beacon-gateway/internal/settings"
)

func newStore(t *testing.T) *settings.Store {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return settings.NewStore(d)
}

func TestGetIntSeededDefault(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Migration 0004 seeds clip_retention_days = 30.
	got, err := s.GetInt(ctx, settings.KeyClipRetentionDays, 0)
	if err != nil {
		t.Fatalf("GetInt: %v", err)
	}
	if got != settings.DefaultClipRetentionDays {
		t.Errorf("seeded retention = %d, want %d", got, settings.DefaultClipRetentionDays)
	}
}

func TestSetIntRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.SetInt(ctx, settings.KeyClipRetentionDays, 14); err != nil {
		t.Fatalf("SetInt: %v", err)
	}
	got, err := s.GetInt(ctx, settings.KeyClipRetentionDays, 0)
	if err != nil {
		t.Fatalf("GetInt: %v", err)
	}
	if got != 14 {
		t.Errorf("after set, retention = %d, want 14", got)
	}
}

func TestGetIntMissingKeyReturnsDefault(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	got, err := s.GetInt(ctx, "does_not_exist", 99)
	if err != nil {
		t.Fatalf("GetInt: %v", err)
	}
	if got != 99 {
		t.Errorf("missing key = %d, want 99 (default)", got)
	}
}
