package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/tarazel/beacon-gateway/internal/auth"
)

func NewRouter(h *Handlers, jwtIssuer *auth.JWTIssuer, store *auth.Store, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.Healthz)
	mux.HandleFunc("POST /api/auth/apple", h.AppleSignIn)
	mux.HandleFunc("POST /api/auth/apple/callback", h.AppleCallback)
	mux.HandleFunc("POST /api/auth/google", h.GoogleSignIn)
	mux.HandleFunc("POST /api/auth/refresh", h.Refresh)

	protected := auth.Middleware(jwtIssuer)
	// mediaProtected also accepts the long-lived media-scoped token the
	// notification service extension uses (it can't refresh the access token).
	mediaProtected := auth.MediaMiddleware(jwtIssuer)
	adminOnly := auth.AdminOnly(store)
	// admin wraps a handler so it runs behind Middleware (auth) then AdminOnly (role).
	admin := func(next http.Handler) http.Handler { return protected(adminOnly(next)) }

	mux.Handle("POST /api/devices", protected(http.HandlerFunc(h.RegisterDevice)))
	mux.Handle("GET /api/mute", protected(http.HandlerFunc(h.GetMute)))
	mux.Handle("POST /api/mute", protected(http.HandlerFunc(h.SetMute)))
	mux.Handle("DELETE /api/mute", protected(http.HandlerFunc(h.SetMute)))
	mux.Handle("GET /api/me", protected(http.HandlerFunc(h.GetMe)))
	mux.Handle("GET /api/settings/clips", protected(http.HandlerFunc(h.GetClipSettings)))
	mux.Handle("PUT /api/settings/clips", admin(http.HandlerFunc(h.PutClipSettings)))
	// System health is an owner/admin diagnostic surface (storage, detector,
	// versions, mqtt) — gated like the other admin settings routes.
	mux.Handle("GET /api/system/health", admin(http.HandlerFunc(h.SystemHealth)))
	// Per-user notification rules (label/zone/score/quiet-hours/cooldown). Each
	// user manages only their own — no admin gate.
	mux.Handle("GET /api/notification-rules", protected(http.HandlerFunc(h.GetNotificationRules)))
	mux.Handle("PUT /api/notification-rules", protected(http.HandlerFunc(h.PutNotificationRules)))
	mux.Handle("POST /api/checkout", admin(http.HandlerFunc(h.CreateCheckout)))
	mux.Handle("GET /api/subscription", protected(http.HandlerFunc(h.GetSubscription)))
	mux.Handle("POST /api/invites", admin(http.HandlerFunc(h.CreateInvite)))
	mux.Handle("GET /api/invites", admin(http.HandlerFunc(h.ListInvites)))
	mux.Handle("DELETE /api/invites/{code}", admin(http.HandlerFunc(h.DeleteInvite)))
	mux.Handle("GET /api/events", protected(http.HandlerFunc(h.ListEvents)))
	// Literal /search takes precedence over the {id} wildcard in Go 1.22+ routing.
	mux.Handle("GET /api/events/search", protected(http.HandlerFunc(h.SearchEvents)))
	mux.Handle("GET /api/events/{id}", protected(http.HandlerFunc(h.GetEvent)))
	// Media-scoped: the NSE reads this (with the media token) to render a banner
	// from a privacy-minimal relay push, which carries only event_id.
	mux.Handle("GET /api/events/{id}/push", mediaProtected(http.HandlerFunc(h.EventPushMeta)))
	mux.Handle("GET /api/events/{id}/snapshot", mediaProtected(http.HandlerFunc(h.EventSnapshot)))
	mux.Handle("GET /api/events/{id}/clip", mediaProtected(http.HandlerFunc(h.EventClip)))
	mux.Handle("HEAD /api/events/{id}/clip", mediaProtected(http.HandlerFunc(h.EventClip)))
	mux.Handle("PUT /api/events/{id}/keep", protected(http.HandlerFunc(h.SetEventKeep)))
	mux.Handle("GET /api/cameras", protected(http.HandlerFunc(h.ListCameras)))
	mux.Handle("GET /api/cameras/{id}/snapshot", protected(http.HandlerFunc(h.CameraSnapshot)))
	mux.Handle("GET /api/cameras/{id}/live", protected(http.HandlerFunc(h.CameraLive)))
	mux.Handle("POST /api/cameras/{id}/webrtc", protected(http.HandlerFunc(h.CameraWebRTC)))
	// HLS off-network live view. Its own middleware also accepts the token from a
	// `token` query param (AVPlayer can't set headers on HLS segment requests).
	hlsProtected := auth.HLSMiddleware(jwtIssuer)
	mux.Handle("GET /api/cameras/{id}/hls/index.m3u8", hlsProtected(http.HandlerFunc(h.HLSIndex)))
	mux.Handle("GET /api/cameras/{id}/hls/r", hlsProtected(http.HandlerFunc(h.HLSResource)))

	return logging(log)(mux)
}

func logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(rw, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"dur_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
