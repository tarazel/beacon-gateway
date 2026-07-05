package auth

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
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return NewStore(d), ctx
}

func TestMuteRoundtrip(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.FindOrCreateUser(ctx, "apple-sub-mute", "mute@example.com", "Muter", RoleMember)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Not muted initially.
	if until, err := s.MutedUntil(ctx, u.ID); err != nil || until != nil {
		t.Fatalf("expected not muted: until=%v err=%v", until, err)
	}

	// Mute for 1h -> reads back as a future expiry.
	future := time.Now().Add(time.Hour)
	if err := s.SetMutedUntil(ctx, u.ID, &future); err != nil {
		t.Fatalf("set mute: %v", err)
	}
	until, err := s.MutedUntil(ctx, u.ID)
	if err != nil || until == nil {
		t.Fatalf("expected muted: until=%v err=%v", until, err)
	}
	if until.Unix() != future.Unix() {
		t.Errorf("muted_until mismatch: got %v want ~%v", until.Unix(), future.Unix())
	}

	// An expired mute reads as nil (not muted).
	past := time.Now().Add(-time.Minute)
	if err := s.SetMutedUntil(ctx, u.ID, &past); err != nil {
		t.Fatalf("set past: %v", err)
	}
	if until, err := s.MutedUntil(ctx, u.ID); err != nil || until != nil {
		t.Errorf("expired mute should read nil: until=%v err=%v", until, err)
	}

	// Clearing returns to not-muted.
	if err := s.SetMutedUntil(ctx, u.ID, &future); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	if err := s.SetMutedUntil(ctx, u.ID, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if until, err := s.MutedUntil(ctx, u.ID); err != nil || until != nil {
		t.Errorf("cleared mute should read nil: until=%v err=%v", until, err)
	}
}

func TestAllowlistRoundtrip(t *testing.T) {
	s, ctx := newTestStore(t)

	if err := s.AllowEmail(ctx, "Alice@Example.COM", "wife"); err != nil {
		t.Fatalf("allow: %v", err)
	}

	ok, err := s.IsEmailAllowed(ctx, "alice@example.com")
	if err != nil || !ok {
		t.Errorf("expected canonicalized email to be allowed: ok=%v err=%v", ok, err)
	}

	ok, err = s.IsEmailAllowed(ctx, "ALICE@example.com")
	if err != nil || !ok {
		t.Errorf("lookup should be case-insensitive: ok=%v err=%v", ok, err)
	}

	list, err := s.ListAllowedEmails(ctx)
	if err != nil || len(list) != 1 || list[0].Email != "alice@example.com" || list[0].Note != "wife" {
		t.Errorf("list: %+v err=%v", list, err)
	}

	// Re-allow with different note updates note
	if err := s.AllowEmail(ctx, "alice@example.com", "spouse"); err != nil {
		t.Fatalf("re-allow: %v", err)
	}
	list, _ = s.ListAllowedEmails(ctx)
	if list[0].Note != "spouse" {
		t.Errorf("note not updated: %q", list[0].Note)
	}

	existed, err := s.RevokeEmail(ctx, "alice@example.com")
	if err != nil || !existed {
		t.Errorf("revoke: existed=%v err=%v", existed, err)
	}
	ok, _ = s.IsEmailAllowed(ctx, "alice@example.com")
	if ok {
		t.Error("email should not be allowed after revoke")
	}

	existed, _ = s.RevokeEmail(ctx, "never@example.com")
	if existed {
		t.Error("revoking unknown email should report existed=false")
	}
}

func TestDeleteUserCascades(t *testing.T) {
	s, ctx := newTestStore(t)

	user, err := s.FindOrCreateUser(ctx, "apple-sub-123", "carol@example.com", "Carol", RoleMember)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Insert a device + a refresh token
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, apns_token, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		"dev-1", user.ID, "apns-token", 1, 1,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, _, err := s.IssueRefreshToken(ctx, user.ID, 60_000_000_000); err != nil {
		t.Fatalf("issue refresh: %v", err)
	}

	devices, tokens, err := s.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if devices != 1 || tokens != 1 {
		t.Errorf("expected 1 device + 1 token removed, got devices=%d tokens=%d", devices, tokens)
	}

	if u, err := s.GetUser(ctx, user.ID); err != nil || u != nil {
		t.Errorf("user should be gone: u=%v err=%v", u, err)
	}

	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM devices WHERE user_id = ?`, user.ID).Scan(&n)
	if n != 0 {
		t.Errorf("device row should be deleted by CASCADE, got %d remaining", n)
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM refresh_tokens WHERE user_id = ?`, user.ID).Scan(&n)
	if n != 0 {
		t.Errorf("refresh_tokens should be deleted by CASCADE, got %d remaining", n)
	}
}

func TestRevokeAllRefreshTokens(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.FindOrCreateUser(ctx, "sub-1", "dave@example.com", "Dave", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := s.IssueRefreshToken(ctx, user.ID, 60_000_000_000); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.RevokeAllRefreshTokens(ctx, user.ID)
	if err != nil || n != 3 {
		t.Errorf("expected 3 revoked, got n=%d err=%v", n, err)
	}
	// Idempotent — a second call should find nothing left to revoke.
	n, err = s.RevokeAllRefreshTokens(ctx, user.ID)
	if err != nil || n != 0 {
		t.Errorf("second call should revoke 0, got n=%d err=%v", n, err)
	}
}

func TestFindUserByIDOrEmail(t *testing.T) {
	s, ctx := newTestStore(t)
	user, _ := s.FindOrCreateUser(ctx, "sub-2", "Erin@Example.com", "Erin", RoleMember)

	got, err := s.FindUserByIDOrEmail(ctx, user.ID)
	if err != nil || got == nil || got.ID != user.ID {
		t.Errorf("by id: got=%+v err=%v", got, err)
	}
	got, err = s.FindUserByIDOrEmail(ctx, "ERIN@example.com")
	if err != nil || got == nil || got.ID != user.ID {
		t.Errorf("by email (case-insensitive): got=%+v err=%v", got, err)
	}
	got, err = s.FindUserByIDOrEmail(ctx, "nobody@example.com")
	if err != nil || got != nil {
		t.Errorf("missing should return nil, got=%+v err=%v", got, err)
	}
}

func TestRoleAndCameraScope(t *testing.T) {
	s, ctx := newTestStore(t)

	// New users default to member.
	member, err := s.FindOrCreateUser(ctx, "sub-member", "m@example.com", "Mem", "")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	if member.Role != RoleMember {
		t.Fatalf("expected default role member, got %q", member.Role)
	}

	// An unscoped member sees all cameras.
	cams, all, err := s.AccessibleCameras(ctx, member.ID)
	if err != nil || !all || len(cams) != 0 {
		t.Fatalf("unscoped member should see all: cams=%v all=%v err=%v", cams, all, err)
	}

	// Scope the member to two cameras (dupes collapse).
	if err := s.SetUserCameras(ctx, member.ID, []string{"front_door", "garage", "front_door"}); err != nil {
		t.Fatalf("set cameras: %v", err)
	}
	cams, all, err = s.AccessibleCameras(ctx, member.ID)
	if err != nil || all || len(cams) != 2 {
		t.Fatalf("scoped member: cams=%v all=%v err=%v", cams, all, err)
	}

	// Promote to admin -> sees all again regardless of scope rows.
	if err := s.SetUserRole(ctx, member.ID, RoleAdmin); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if _, all, _ := s.AccessibleCameras(ctx, member.ID); !all {
		t.Fatalf("admin should see all cameras")
	}

	// Demote + clear scope returns to sees-all.
	if err := s.SetUserRole(ctx, member.ID, RoleMember); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if err := s.SetUserCameras(ctx, member.ID, nil); err != nil {
		t.Fatalf("clear scope: %v", err)
	}
	if _, all, _ := s.AccessibleCameras(ctx, member.ID); !all {
		t.Fatalf("cleared scope should see all")
	}

	if err := s.SetUserRole(ctx, member.ID, "bogus"); err == nil {
		t.Fatalf("expected error for invalid role")
	}
}

func TestCameraMuteRoundtrip(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.FindOrCreateUser(ctx, "apple-sub-cammute", "cam@example.com", "Cammer", RoleMember)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// No camera mutes initially.
	if m, err := s.CameraMutes(ctx, u.ID); err != nil || len(m) != 0 {
		t.Fatalf("expected no camera mutes: m=%v err=%v", m, err)
	}

	// Mute "deimos" for 1h; "porch" stays unmuted.
	future := time.Now().Add(time.Hour)
	if err := s.SetCameraMute(ctx, u.ID, "deimos", &future); err != nil {
		t.Fatalf("set camera mute: %v", err)
	}
	m, err := s.CameraMutes(ctx, u.ID)
	if err != nil {
		t.Fatalf("camera mutes: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 muted camera, got %d (%v)", len(m), m)
	}
	if got, ok := m["deimos"]; !ok || got.Unix() != future.Unix() {
		t.Errorf("deimos mute mismatch: got=%v ok=%v want ~%v", got, ok, future.Unix())
	}

	// Expired camera mute is filtered out.
	past := time.Now().Add(-time.Minute)
	if err := s.SetCameraMute(ctx, u.ID, "deimos", &past); err != nil {
		t.Fatalf("set past: %v", err)
	}
	if m, err := s.CameraMutes(ctx, u.ID); err != nil || len(m) != 0 {
		t.Errorf("expired camera mute should be filtered: m=%v err=%v", m, err)
	}

	// Re-mute then clear (nil) removes the row.
	if err := s.SetCameraMute(ctx, u.ID, "deimos", &future); err != nil {
		t.Fatalf("re-mute: %v", err)
	}
	if err := s.SetCameraMute(ctx, u.ID, "deimos", nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if m, err := s.CameraMutes(ctx, u.ID); err != nil || len(m) != 0 {
		t.Errorf("cleared camera mute should be gone: m=%v err=%v", m, err)
	}
}
