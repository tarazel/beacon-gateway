package auth

import (
	"testing"
)

func TestFindOrCreateUserWritesAppleIdentity(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.FindOrCreateUser(ctx, "apple-123", "a@example.com", "Ann", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetUserByProviderIdentity(ctx, ProviderApple, "apple-123")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got == nil || got.ID != u.ID {
		t.Fatalf("provider identity lookup did not return the created user: %+v", got)
	}
	// A second call must be idempotent (no duplicate identity / user).
	u2, err := s.FindOrCreateUser(ctx, "apple-123", "a@example.com", "Ann", RoleMember)
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if u2.ID != u.ID {
		t.Fatalf("expected same user id, got %s vs %s", u2.ID, u.ID)
	}
}

func TestGetUserByProviderIdentityUnknown(t *testing.T) {
	s, ctx := newTestStore(t)
	got, err := s.GetUserByProviderIdentity(ctx, ProviderGoogle, "nope")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for unknown identity, got %+v", got)
	}
}

func TestCreateUserWithGoogleIdentitySynthesizesAppleAnchor(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.CreateUserWithIdentity(ctx, ProviderGoogle, "goog-1", "", "g@example.com", "Gus", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.AppleSub != "google:goog-1" {
		t.Fatalf("expected synthetic apple_sub anchor 'google:goog-1', got %q", u.AppleSub)
	}
	got, err := s.GetUserByProviderIdentity(ctx, ProviderGoogle, "goog-1")
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("google identity lookup failed: %+v err=%v", got, err)
	}
	// The synthetic anchor must not be discoverable as a Google identity twice, and
	// must be globally unique across a second Google user.
	u2, err := s.CreateUserWithIdentity(ctx, ProviderGoogle, "goog-2", "", "g2@example.com", "", RoleMember)
	if err != nil {
		t.Fatalf("create second google user: %v", err)
	}
	if u2.AppleSub == u.AppleSub {
		t.Fatalf("two google users share the same apple_sub anchor: %q", u2.AppleSub)
	}
}

func TestGetUserByEmailCaseInsensitive(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.FindOrCreateUser(ctx, "apple-e", "Mixed@Example.com", "Mel", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetUserByEmail(ctx, "mixed@example.com")
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("case-insensitive email lookup failed: %+v err=%v", got, err)
	}
	if none, _ := s.GetUserByEmail(ctx, ""); none != nil {
		t.Fatalf("empty email must not match a user")
	}
}

func TestLinkIdentityCrossProvider(t *testing.T) {
	s, ctx := newTestStore(t)
	// Existing Apple user.
	u, err := s.FindOrCreateUser(ctx, "apple-link", "link@example.com", "Lee", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Link a Google identity (same person, different platform).
	if err := s.LinkIdentity(ctx, u.ID, ProviderGoogle, "goog-link", "link@example.com"); err != nil {
		t.Fatalf("link: %v", err)
	}
	got, err := s.GetUserByProviderIdentity(ctx, ProviderGoogle, "goog-link")
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("expected google identity to resolve to the apple user: %+v err=%v", got, err)
	}
	// Idempotent re-link is a no-op, not an error.
	if err := s.LinkIdentity(ctx, u.ID, ProviderGoogle, "goog-link", "link@example.com"); err != nil {
		t.Fatalf("relink: %v", err)
	}

	// An identity already bound to one user must not be silently moved to another.
	other, err := s.FindOrCreateUser(ctx, "apple-other", "other@example.com", "Ott", RoleMember)
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if err := s.LinkIdentity(ctx, other.ID, ProviderGoogle, "goog-link", "other@example.com"); err != nil {
		t.Fatalf("conflicting link should not error: %v", err)
	}
	got, err = s.GetUserByProviderIdentity(ctx, ProviderGoogle, "goog-link")
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("existing identity binding must win; got %+v err=%v", got, err)
	}
}
