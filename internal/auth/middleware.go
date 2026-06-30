package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey int

const userIDKey ctxKey = 0

func WithUser(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

func UserID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(userIDKey).(string)
	return v, ok && v != ""
}

// Middleware authorizes general API endpoints. It rejects media-scoped tokens —
// those are only valid on media endpoints (see MediaMiddleware).
func Middleware(issuer *JWTIssuer) func(http.Handler) http.Handler {
	return authMiddleware(issuer, false)
}

// MediaMiddleware authorizes media endpoints (snapshots/clips) with either a
// normal access token or a media-scoped token. The latter lets the notification
// service extension fetch snapshots without being able to refresh.
func MediaMiddleware(issuer *JWTIssuer) func(http.Handler) http.Handler {
	return authMiddleware(issuer, true)
}

func authMiddleware(issuer *JWTIssuer, allowMedia bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(h, prefix) {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			claims, err := issuer.Parse(strings.TrimPrefix(h, prefix))
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			if claims.Scope == ScopeMedia && !allowMedia {
				http.Error(w, "token not valid for this endpoint", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), claims.UserID)))
		})
	}
}

// AdminOnly wraps a handler so only users with the admin role may reach it. It
// must run inside Middleware (it reads the user id from the request context and
// looks the role up fresh, so a role change takes effect without re-auth).
func AdminOnly(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := UserID(r.Context())
			if !ok {
				http.Error(w, "auth required", http.StatusUnauthorized)
				return
			}
			u, err := store.GetUser(r.Context(), userID)
			if err != nil {
				http.Error(w, "role lookup failed", http.StatusInternalServerError)
				return
			}
			if u == nil || !u.IsAdmin() {
				http.Error(w, "admin only", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
