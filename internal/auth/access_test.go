package auth

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRevokeAccessDisablesAccountUntilAllowed(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.CreateUserWithIdentity(ctx, ProviderApple, "sub-r", "sub-r", "Rae@Example.com", "Rae", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	other, err := s.CreateUserWithIdentity(ctx, ProviderApple, "sub-o", "sub-o", "other@example.com", "Other", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	raw, _, err := s.IssueRefreshToken(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, apns_token, created_at, last_seen_at) VALUES ('d', ?, 'tok', 0, 0)`, u.ID); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	res, err := s.RevokeAccess(ctx, " rae@example.com ")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.Users != 1 || res.Tokens != 1 || res.Devices != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if active, _ := s.IsUserActive(ctx, u.ID); active {
		t.Fatal("revoked user still active")
	}
	if active, _ := s.IsUserActive(ctx, other.ID); !active {
		t.Fatal("unrelated user was disabled")
	}
	if _, err := s.ConsumeRefreshToken(ctx, raw); err == nil {
		t.Fatal("revoked refresh token still works")
	}

	if err := s.AllowEmail(ctx, "rae@example.com", ""); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if active, _ := s.IsUserActive(ctx, u.ID); !active {
		t.Fatal("allow should re-enable the account")
	}
	if revoked, _ := s.IsEmailRevoked(ctx, "rae@example.com"); revoked {
		t.Fatal("allow should lift the email block")
	}
}

// An account is revoked through any email linked to it, not only its first one.
func TestRevokeAccessByLinkedIdentityEmail(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.CreateUserWithIdentity(ctx, ProviderApple, "sub-l", "sub-l", "first@example.com", "L", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.LinkIdentity(ctx, u.ID, ProviderGoogle, "g-l", "second@example.com"); err != nil {
		t.Fatalf("link: %v", err)
	}
	if res, err := s.RevokeAccess(ctx, "second@example.com"); err != nil || res.Users != 1 {
		t.Fatalf("revoke: %+v err=%v", res, err)
	}
	if active, _ := s.IsUserActive(ctx, u.ID); active {
		t.Fatal("user still active")
	}
}

func TestRefreshTokenRedeemsOnceUnderConcurrency(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.FindOrCreateUser(ctx, "sub-c", "c@example.com", "C", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	raw, _, err := s.IssueRefreshToken(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := countSuccesses(20, func(int) bool { _, err := s.ConsumeRefreshToken(ctx, raw); return err == nil }); got != 1 {
		t.Fatalf("token redeemed %d times", got)
	}

	expired, _, err := s.IssueRefreshToken(ctx, u.ID, -time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.ConsumeRefreshToken(ctx, expired); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestInviteAdmitsOneUserUnderConcurrency(t *testing.T) {
	s, ctx := newTestStore(t)
	code, _ := NewInviteCode()
	if _, err := s.CreateInvite(ctx, code, RoleAdmin, []string{"porch"}, "", "", nil); err != nil {
		t.Fatalf("invite: %v", err)
	}
	got := countSuccesses(20, func(i int) bool {
		sub := "sub-" + strings.Repeat("x", i+1)
		u, err := s.CreateUserFromInvite(ctx, NewUser{Provider: ProviderApple, Sub: sub}, code)
		if err != nil {
			if !errors.Is(err, ErrInviteUnavailable) {
				t.Errorf("unexpected error: %v", err)
			}
			return false
		}
		if u.Role != RoleAdmin {
			t.Errorf("role not taken from the invite: %s", u.Role)
		}
		if cams, _ := s.GetUserCameras(ctx, u.ID); len(cams) != 1 || cams[0] != "porch" {
			t.Errorf("camera scope not applied: %v", cams)
		}
		return true
	})
	if got != 1 {
		t.Fatalf("invite admitted %d users", got)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("rejected redemptions left accounts behind: %d users", n)
	}
}

func countSuccesses(n int, fn func(i int) bool) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	total := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if fn(i) {
				mu.Lock()
				total++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	return total
}
