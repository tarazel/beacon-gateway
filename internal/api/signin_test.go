package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hydak/beacon-gateway/internal/auth"
	"github.com/hydak/beacon-gateway/internal/config"
	"github.com/hydak/beacon-gateway/internal/db"
)

// newSignInHandlers builds a Handlers with just the pieces the provider sign-in
// path touches (store, jwt, config TTLs, allowlist/admin maps). The allowlist map
// is returned so tests can mutate it mid-run (e.g. to prove that linking a second
// provider to an existing user is NOT re-gated).
func newSignInHandlers(t *testing.T) (*Handlers, map[string]struct{}) {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	allowlist := map[string]struct{}{}
	cfg := &config.Config{}
	cfg.Auth.RefreshTokenTTL = 24 * time.Hour
	cfg.Auth.MediaTokenTTL = 24 * time.Hour
	h := &Handlers{
		cfg:         cfg,
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		db:          d,
		users:       auth.NewStore(d),
		jwt:         auth.NewJWTIssuer([]byte("test-signing-key-at-least-32-bytes!!"), 15*time.Minute),
		allowlist:   allowlist,
		adminEmails: map[string]struct{}{},
	}
	return h, allowlist
}

func callSignIn(t *testing.T, h *Handlers, in providerSignIn) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/"+in.provider, nil)
	w := httptest.NewRecorder()
	h.completeProviderSignIn(w, req, in)
	return w
}

func decodeUserID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.UserID == "" || resp.AccessToken == "" || resp.RefreshToken == "" || resp.MediaToken == "" {
		t.Fatalf("incomplete token response: %+v", resp)
	}
	return resp.UserID
}

func TestSignInNewUserRequiresAllowlistOrInvite(t *testing.T) {
	h, _ := newSignInHandlers(t)
	w := callSignIn(t, h, providerSignIn{
		provider: auth.ProviderApple, sub: "apple-x", email: "nope@example.com",
		emailVerified: true, rejectMsg: "nope",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for un-allowlisted new user, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignInAppleThenGoogleLinksByEmail(t *testing.T) {
	h, allowlist := newSignInHandlers(t)
	allowlist["shared@example.com"] = struct{}{}

	// First: Apple sign-in creates the account (allowlisted).
	appleUID := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderApple, sub: "apple-shared", email: "shared@example.com",
		emailVerified: true, name: "Sam",
	}))

	// Now REMOVE the email from the allowlist — a returning/linking user must not be
	// re-gated. A Google sign-in with the same verified email links to the same user.
	delete(allowlist, "shared@example.com")
	googleUID := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderGoogle, sub: "goog-shared", email: "shared@example.com",
		emailVerified: true, name: "Sam",
	}))

	if googleUID != appleUID {
		t.Fatalf("expected Google sign-in to resolve to the same user; apple=%s google=%s", appleUID, googleUID)
	}

	// And the Google identity now resolves to that user directly on a repeat sign-in.
	ctx := context.Background()
	got, err := h.users.GetUserByProviderIdentity(ctx, auth.ProviderGoogle, "goog-shared")
	if err != nil || got == nil || got.ID != appleUID {
		t.Fatalf("google identity not linked: %+v err=%v", got, err)
	}
}

func TestSignInGoogleUnverifiedEmailDoesNotLink(t *testing.T) {
	h, allowlist := newSignInHandlers(t)
	allowlist["v@example.com"] = struct{}{}

	// Apple user exists with a verified email.
	appleUID := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderApple, sub: "apple-v", email: "v@example.com", emailVerified: true,
	}))

	// A Google sign-in claiming the same email but UNVERIFIED must not link; since
	// it's still allowlisted it creates a separate account (safer than trusting an
	// unverified email to merge into someone else's account).
	googleUID := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderGoogle, sub: "goog-v", email: "v@example.com", emailVerified: false,
	}))
	if googleUID == appleUID {
		t.Fatalf("unverified email must not merge accounts; both are %s", appleUID)
	}
}

func TestSignInReturningIdentityIsIdempotent(t *testing.T) {
	h, allowlist := newSignInHandlers(t)
	allowlist["r@example.com"] = struct{}{}

	first := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderGoogle, sub: "goog-r", email: "r@example.com", emailVerified: true,
	}))
	delete(allowlist, "r@example.com") // returning user must not be re-gated
	second := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderGoogle, sub: "goog-r", email: "r@example.com", emailVerified: true,
	}))
	if first != second {
		t.Fatalf("returning identity should be the same user; %s vs %s", first, second)
	}
}
