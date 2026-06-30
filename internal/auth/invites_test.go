package auth

import (
	"testing"
	"time"
)

func TestInviteLifecycle(t *testing.T) {
	s, ctx := newTestStore(t)

	code, err := NewInviteCode()
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	inv, err := s.CreateInvite(ctx, code, RoleMember, []string{"front_door"}, "brother", "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !inv.Pending() {
		t.Fatalf("fresh invite should be pending")
	}

	got, err := s.GetInvite(ctx, code)
	if err != nil || got == nil {
		t.Fatalf("get: got=%v err=%v", got, err)
	}
	if got.Role != RoleMember || len(got.Cameras) != 1 || got.Cameras[0] != "front_door" || got.Note != "brother" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Single-use: first consume succeeds, second fails.
	user, _ := s.FindOrCreateUser(ctx, "sub-invitee", "b@example.com", "Bro", RoleMember)
	if ok, err := s.ConsumeInvite(ctx, code, user.ID); err != nil || !ok {
		t.Fatalf("first consume should succeed: ok=%v err=%v", ok, err)
	}
	if ok, err := s.ConsumeInvite(ctx, code, user.ID); err != nil || ok {
		t.Fatalf("second consume should fail: ok=%v err=%v", ok, err)
	}
	got, _ = s.GetInvite(ctx, code)
	if got.Pending() || got.ConsumedAt == nil || got.ConsumedBy != user.ID {
		t.Fatalf("consumed invite state wrong: %+v", got)
	}
}

func TestInviteExpiry(t *testing.T) {
	s, ctx := newTestStore(t)

	past := time.Now().Add(-time.Minute)
	code, _ := NewInviteCode()
	if _, err := s.CreateInvite(ctx, code, RoleAdmin, nil, "", "", &past); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, _ := s.GetInvite(ctx, code)
	if got.Pending() {
		t.Fatalf("expired invite should not be pending")
	}
	if ok, _ := s.ConsumeInvite(ctx, code, "someone"); ok {
		t.Fatalf("expired invite should not be consumable")
	}

	// Unknown code -> nil, no error.
	if got, err := s.GetInvite(ctx, "NOPE-NOPE"); err != nil || got != nil {
		t.Fatalf("unknown invite: got=%v err=%v", got, err)
	}
}

func TestInviteCodeFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c, err := NewInviteCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' { // XXXX-XXXX
			t.Fatalf("unexpected code format: %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate code generated: %q", c)
		}
		seen[c] = true
	}
}
