package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tarazel/beacon-gateway/internal/auth"
)

func serve(h *Handlers, method, path, token, body string) *httptest.ResponseRecorder {
	router := NewRouter(h, h.jwt, h.users, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRevokedUserCannotReturn(t *testing.T) {
	h, allowlist := newSignInHandlers(t)
	allowlist["gone@example.com"] = struct{}{}
	in := providerSignIn{provider: auth.ProviderApple, sub: "apple-gone", email: "gone@example.com", emailVerified: true}
	uid := decodeUserID(t, callSignIn(t, h, in))
	access, _, err := h.jwt.Issue(uid)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if w := serve(h, http.MethodGet, "/api/me", access, ""); w.Code != http.StatusOK {
		t.Fatalf("before revoke: %d", w.Code)
	}

	if _, err := h.users.RevokeAccess(context.Background(), "gone@example.com"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if w := serve(h, http.MethodGet, "/api/me", access, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("existing token after revoke: %d", w.Code)
	}
	// Still on the static allowlist, and a known identity: neither lets them back.
	if w := callSignIn(t, h, in); w.Code != http.StatusForbidden {
		t.Errorf("sign-in after revoke: %d", w.Code)
	}
	// Nor without an email on the token.
	noEmail := in
	noEmail.email, noEmail.emailVerified = "", false
	if w := callSignIn(t, h, noEmail); w.Code != http.StatusForbidden {
		t.Errorf("sign-in without email after revoke: %d", w.Code)
	}
}

func TestUnverifiedAdminEmailGetsNothing(t *testing.T) {
	h, _ := newSignInHandlers(t)
	h.adminEmails["boss@example.com"] = struct{}{}
	ctx := context.Background()
	code, _ := auth.NewInviteCode()
	if _, err := h.users.CreateInvite(ctx, code, auth.RoleMember, nil, "", "", nil); err != nil {
		t.Fatalf("invite: %v", err)
	}
	// An invited user who isn't the first: unverified admin email must not promote
	// them or be stored, since a later verified sign-in would link to it.
	if _, err := h.users.FindOrCreateUser(ctx, "owner", "owner@example.com", "Owner", auth.RoleAdmin); err != nil {
		t.Fatalf("owner: %v", err)
	}
	uid := decodeUserID(t, callSignIn(t, h, providerSignIn{
		provider: auth.ProviderGoogle, sub: "g-boss", email: "boss@example.com", inviteCode: code,
	}))
	u, err := h.users.GetUser(ctx, uid)
	if err != nil || u == nil {
		t.Fatalf("get: %v", err)
	}
	if u.Role != auth.RoleMember || u.Email != "" {
		t.Fatalf("unverified email granted something: role=%s email=%q", u.Role, u.Email)
	}
}

func TestSignInRequiresBoundNonce(t *testing.T) {
	h, _ := newSignInHandlers(t)
	h.nonce = auth.NoncePolicy{Origins: []string{"https://gw.example.com"}, Required: true}
	h.apple = auth.NewAppleVerifier("org.example.app")
	// An unverifiable token is rejected before any account work.
	w := serve(h, http.MethodPost, "/api/auth/apple", "", `{"identity_token":"nope"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", w.Code)
	}
}

func TestUnregisterDeviceOnlyRemovesOwn(t *testing.T) {
	h := newTestHandlers(t, nil)
	h.jwt = auth.NewJWTIssuer([]byte("test-signing-key-at-least-32-bytes!!"), time.Hour)
	seedMember(t, h, "user-2")
	mine, _, _ := h.jwt.Issue("user-1")
	theirs, _, _ := h.jwt.Issue("user-2")
	if w := serve(h, http.MethodPost, "/api/devices", mine, `{"apns_token":"abc"}`); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	count := func() (n int) {
		if err := h.db.QueryRow(`SELECT COUNT(1) FROM devices`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if w := serve(h, http.MethodDelete, "/api/devices", theirs, `{"apns_token":"abc"}`); w.Code != http.StatusOK || count() != 1 {
		t.Fatalf("another user removed the device: %d, %d left", w.Code, count())
	}
	if w := serve(h, http.MethodDelete, "/api/devices", mine, `{"apns_token":"abc"}`); w.Code != http.StatusOK || count() != 0 {
		t.Fatalf("unregister: %d, %d left", w.Code, count())
	}
}

func TestRequestBodyIsLimited(t *testing.T) {
	h, _ := newSignInHandlers(t)
	huge := `{"refresh_token":"` + strings.Repeat("a", maxRequestBody) + `"}`
	if w := serve(h, http.MethodPost, "/api/auth/refresh", "", huge); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", w.Code)
	}
}
