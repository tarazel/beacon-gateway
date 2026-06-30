package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func do(t *testing.T, mw func(http.Handler) http.Handler, bearer string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	return rec.Code
}

func TestMiddlewareScopes(t *testing.T) {
	issuer := NewJWTIssuer([]byte("test-signing-key-at-least-32-bytes-long!!"), 15*time.Minute)
	access, _, err := issuer.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	media, _, err := issuer.IssueMedia("user-1", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueMedia: %v", err)
	}

	general := Middleware(issuer)
	mediaMW := MediaMiddleware(issuer)

	cases := []struct {
		name   string
		mw     func(http.Handler) http.Handler
		bearer string
		want   int
	}{
		{"general: access ok", general, access, http.StatusOK},
		{"general: media REJECTED", general, media, http.StatusForbidden},
		{"general: missing token", general, "", http.StatusUnauthorized},
		{"general: garbage token", general, "not-a-jwt", http.StatusUnauthorized},
		{"media: access ok", mediaMW, access, http.StatusOK},
		{"media: media ok", mediaMW, media, http.StatusOK},
		{"media: missing token", mediaMW, "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(t, tc.mw, tc.bearer); got != tc.want {
				t.Fatalf("want %d, got %d", tc.want, got)
			}
		})
	}
}

// A media token must still identify the user (so per-camera scope checks apply).
func TestMediaTokenCarriesUser(t *testing.T) {
	issuer := NewJWTIssuer([]byte("test-signing-key-at-least-32-bytes-long!!"), 15*time.Minute)
	media, _, err := issuer.IssueMedia("user-42", time.Hour)
	if err != nil {
		t.Fatalf("IssueMedia: %v", err)
	}
	claims, err := issuer.Parse(media)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.UserID != "user-42" {
		t.Fatalf("media token sub: want user-42, got %q", claims.UserID)
	}
	if claims.Scope != ScopeMedia {
		t.Fatalf("media token scope: want %q, got %q", ScopeMedia, claims.Scope)
	}
}
