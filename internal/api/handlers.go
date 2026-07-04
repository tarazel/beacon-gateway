package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hydak/beacon-gateway/internal/auth"
	"github.com/hydak/beacon-gateway/internal/cameras"
	"github.com/hydak/beacon-gateway/internal/config"
	"github.com/hydak/beacon-gateway/internal/events"
	"github.com/hydak/beacon-gateway/internal/frigate"
	"github.com/hydak/beacon-gateway/internal/go2rtc"
	"github.com/hydak/beacon-gateway/internal/notifrules"
	"github.com/hydak/beacon-gateway/internal/settings"
)

type Handlers struct {
	cfg         *config.Config
	log         *slog.Logger
	db          *sql.DB
	users       *auth.Store
	jwt         *auth.JWTIssuer
	apple       *auth.AppleVerifier
	events      *events.Store
	frigate     *frigate.Client
	cameras     *cameras.Registry
	go2rtc      *go2rtc.Client
	settings    *settings.Store
	notifrules  *notifrules.Store
	allowlist   map[string]struct{}
	adminEmails map[string]struct{}
}

func NewHandlers(
	cfg *config.Config,
	log *slog.Logger,
	db *sql.DB,
	users *auth.Store,
	jwt *auth.JWTIssuer,
	apple *auth.AppleVerifier,
	eventStore *events.Store,
	frigateClient *frigate.Client,
	camRegistry *cameras.Registry,
	go2rtcClient *go2rtc.Client,
	settingsStore *settings.Store,
	rulesStore *notifrules.Store,
) *Handlers {
	allow := make(map[string]struct{}, len(cfg.Auth.AppleAllowedEmails))
	for _, e := range cfg.Auth.AppleAllowedEmails {
		allow[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	admins := make(map[string]struct{}, len(cfg.Auth.AdminEmails))
	for _, e := range cfg.Auth.AdminEmails {
		admins[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	return &Handlers{
		cfg:         cfg,
		log:         log,
		db:          db,
		users:       users,
		jwt:         jwt,
		apple:       apple,
		events:      eventStore,
		frigate:     frigateClient,
		cameras:     camRegistry,
		go2rtc:      go2rtcClient,
		settings:    settingsStore,
		notifrules:  rulesStore,
		allowlist:   allow,
		adminEmails: admins,
	}
}

func (h *Handlers) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type appleSignInRequest struct {
	IdentityToken string `json:"identity_token"`
	Name          string `json:"name,omitempty"`
	InviteCode    string `json:"invite_code,omitempty"`
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	MediaToken   string    `json:"media_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserID       string    `json:"user_id"`
}

func (h *Handlers) AppleSignIn(w http.ResponseWriter, r *http.Request) {
	var req appleSignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IdentityToken == "" {
		writeError(w, http.StatusBadRequest, "identity_token required")
		return
	}

	id, err := h.apple.Verify(r.Context(), req.IdentityToken)
	if err != nil {
		h.log.Warn("apple verify failed", "err", err)
		writeError(w, http.StatusUnauthorized, "invalid apple token")
		return
	}

	user, err := h.users.GetUserByAppleSub(r.Context(), id.Sub)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}

	if user == nil {
		ctx := r.Context()
		allowed := h.emailAllowed(ctx, id.Email)

		// A pending invite admits a user who isn't on the allowlist, and carries
		// the role + camera scope the admin chose for them.
		var invite *auth.Invite
		if code := normalizeInviteCode(req.InviteCode); code != "" {
			if inv, err := h.users.GetInvite(ctx, code); err == nil && inv != nil && inv.Pending() {
				invite = inv
			}
		}

		if !allowed && invite == nil {
			h.log.Warn("apple sign-in rejected: not allowlisted and no valid invite", "sub", id.Sub, "email", id.Email)
			writeError(w, http.StatusForbidden, "this Apple ID is not authorized — ask the owner for an invite")
			return
		}

		role := h.roleForNewUser(ctx, id.Email)
		if invite != nil {
			role = invite.Role
		}
		user, err = h.users.FindOrCreateUser(ctx, id.Sub, id.Email, req.Name, role)
		if err != nil {
			h.log.Error("create user failed", "err", err)
			writeError(w, http.StatusInternalServerError, "user create failed")
			return
		}

		if invite != nil {
			if len(invite.Cameras) > 0 {
				if err := h.users.SetUserCameras(ctx, user.ID, invite.Cameras); err != nil {
					h.log.Warn("apply invite camera scope failed", "user_id", user.ID, "err", err)
				}
			}
			if ok, err := h.users.ConsumeInvite(ctx, invite.Code, user.ID); err != nil || !ok {
				h.log.Warn("consume invite failed/raced", "code", invite.Code, "ok", ok, "err", err)
			}
		}
		h.log.Info("new user created", "user_id", user.ID, "role", user.Role, "email", id.Email, "via_invite", invite != nil)
	}

	h.issueTokens(w, r.Context(), user.ID)
}

// normalizeInviteCode upper-cases and trims an invite code for lookup.
func normalizeInviteCode(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// roleForNewUser decides the role for a brand-new user: admin if the email is in
// ADMIN_EMAILS, or if this is the first user on the instance (the owner bootstrap);
// otherwise member.
func (h *Handlers) roleForNewUser(ctx context.Context, email string) string {
	if e := strings.ToLower(strings.TrimSpace(email)); e != "" {
		if _, ok := h.adminEmails[e]; ok {
			return auth.RoleAdmin
		}
	}
	if n, err := h.users.CountUsers(ctx); err == nil && n == 0 {
		return auth.RoleAdmin
	}
	return auth.RoleMember
}

func (h *Handlers) emailAllowed(ctx context.Context, email string) bool {
	if email == "" {
		return false
	}
	e := strings.ToLower(strings.TrimSpace(email))
	if _, ok := h.allowlist[e]; ok {
		return true
	}
	ok, err := h.users.IsEmailAllowed(ctx, e)
	if err != nil {
		h.log.Warn("allowlist lookup failed", "err", err)
		return false
	}
	return ok
}

func (h *Handlers) issueTokens(w http.ResponseWriter, ctx context.Context, userID string) {
	access, exp, err := h.jwt.Issue(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	refresh, _, err := h.users.IssueRefreshToken(ctx, userID, h.cfg.Auth.RefreshTokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "refresh issue failed")
		return
	}
	media, _, err := h.jwt.IssueMedia(userID, h.cfg.Auth.MediaTokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "media token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		MediaToken:   media,
		ExpiresAt:    exp,
		UserID:       userID,
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token required")
		return
	}
	tok, err := h.users.ConsumeRefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	if err := h.users.RevokeRefreshToken(r.Context(), tok.ID); err != nil {
		h.log.Warn("failed to revoke old refresh token", "err", err)
	}
	h.issueTokens(w, r.Context(), tok.UserID)
}

type meResponse struct {
	UserID     string   `json:"user_id"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	IsAdmin    bool     `json:"is_admin"`
	AllCameras bool     `json:"all_cameras"` // true = sees every camera
	Cameras    []string `json:"cameras"`     // explicit scope when AllCameras is false
}

// GetMe returns the caller's identity, role, and camera scope so the client can
// adapt its UI (e.g. show admin-only screens, hide cameras out of scope).
func (h *Handlers) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	u, err := h.users.GetUser(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	if u == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	cams, all, err := h.users.AccessibleCameras(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access lookup failed")
		return
	}
	if cams == nil {
		cams = []string{}
	}
	writeJSON(w, http.StatusOK, meResponse{
		UserID:     u.ID,
		Email:      u.Email,
		Name:       u.Name,
		Role:       u.Role,
		IsAdmin:    u.IsAdmin(),
		AllCameras: all,
		Cameras:    cams,
	})
}

type registerDeviceRequest struct {
	APNsToken  string `json:"apns_token"`
	AppVersion string `json:"app_version,omitempty"`
	// Platform routes the push backend: "ios" (APNs, default) or "android" (FCM).
	// Empty defaults to "ios" for older iOS clients that don't send it.
	Platform string `json:"platform,omitempty"`
}

func (h *Handlers) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req registerDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.APNsToken == "" {
		writeError(w, http.StatusBadRequest, "apns_token required")
		return
	}

	platform := req.Platform
	if platform == "" {
		platform = "ios"
	}
	now := time.Now().Unix()
	id := uuid.NewString()
	_, err := h.db.ExecContext(r.Context(), `
		INSERT INTO devices (id, user_id, apns_token, platform, app_version, last_seen_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(apns_token) DO UPDATE SET
			user_id = excluded.user_id,
			platform = excluded.platform,
			app_version = excluded.app_version,
			last_seen_at = excluded.last_seen_at
	`, id, userID, req.APNsToken, platform, nullableStr(req.AppVersion), now, now)
	if err != nil {
		h.log.Error("device register failed", "err", err)
		writeError(w, http.StatusInternalServerError, "register failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type muteRequest struct {
	DurationSeconds int64  `json:"duration_seconds"`
	Camera          string `json:"camera"` // empty = global mute
}

type cameraMuteState struct {
	Camera     string    `json:"camera"`
	MutedUntil time.Time `json:"muted_until"`
}

type muteResponse struct {
	MutedUntil *time.Time        `json:"muted_until"` // global mute, null if not muted
	Cameras    []cameraMuteState `json:"cameras"`     // active per-camera mutes
}

// GetMute returns the caller's global mute expiry plus any active per-camera mutes.
func (h *Handlers) GetMute(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	h.writeMuteState(w, r, userID)
}

// SetMute mutes alerts for duration_seconds, or clears the mute (DELETE, or POST
// with duration_seconds <= 0). Capped at 24h. A non-empty `camera` targets that
// camera; otherwise the global per-user mute is set. Returns the full mute state.
func (h *Handlers) SetMute(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var until *time.Time
	var camera string
	if r.Method == http.MethodPost {
		var req muteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		camera = strings.TrimSpace(req.Camera)
		if req.DurationSeconds > 0 {
			const maxMute = int64(24 * 3600)
			if req.DurationSeconds > maxMute {
				req.DurationSeconds = maxMute
			}
			// Whole seconds only: the iOS ISO8601 decoder rejects fractional seconds.
			t := time.Now().Add(time.Duration(req.DurationSeconds) * time.Second).Truncate(time.Second).UTC()
			until = &t
		}
	}

	var err error
	if camera != "" {
		err = h.users.SetCameraMute(r.Context(), userID, camera, until)
	} else {
		err = h.users.SetMutedUntil(r.Context(), userID, until)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mute update failed")
		return
	}
	h.writeMuteState(w, r, userID)
}

func (h *Handlers) writeMuteState(w http.ResponseWriter, r *http.Request, userID string) {
	until, err := h.users.MutedUntil(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mute lookup failed")
		return
	}
	cams, err := h.users.CameraMutes(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mute lookup failed")
		return
	}
	resp := muteResponse{MutedUntil: until, Cameras: []cameraMuteState{}}
	for cam, t := range cams {
		resp.Cameras = append(resp.Cameras, cameraMuteState{Camera: cam, MutedUntil: t})
	}
	sort.Slice(resp.Cameras, func(i, j int) bool { return resp.Cameras[i].Camera < resp.Cameras[j].Camera })
	writeJSON(w, http.StatusOK, resp)
}

const (
	minRetentionDays = 1
	maxRetentionDays = 3650
)

type clipSettingsResponse struct {
	RetentionDays int `json:"retention_days"`
}

// GetClipSettings returns the gateway-wide clip cache retention window (days).
func (h *Handlers) GetClipSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.UserID(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	days, err := h.settings.GetInt(r.Context(), settings.KeyClipRetentionDays, settings.DefaultClipRetentionDays)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "settings lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, clipSettingsResponse{RetentionDays: days})
}

// PutClipSettings updates the clip cache retention window. The value is clamped
// to [1, 3650] days.
func (h *Handlers) PutClipSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.UserID(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req clipSettingsResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	days := req.RetentionDays
	if days < minRetentionDays {
		days = minRetentionDays
	}
	if days > maxRetentionDays {
		days = maxRetentionDays
	}
	if err := h.settings.SetInt(r.Context(), settings.KeyClipRetentionDays, days); err != nil {
		writeError(w, http.StatusInternalServerError, "settings update failed")
		return
	}
	writeJSON(w, http.StatusOK, clipSettingsResponse{RetentionDays: days})
}

type keepRequest struct {
	Keep bool `json:"keep"`
}

type keepResponse struct {
	EventID string `json:"event_id"`
	Keep    bool   `json:"keep"`
}

// SetEventKeep pins or unpins an event's clip so the cache pruner skips it. When
// pinning, it best-effort caches the clip now so it survives even if Frigate
// later prunes the underlying recording.
func (h *Handlers) SetEventKeep(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "event id required")
		return
	}
	// Pinning is a shared-archive action: any user with access to the event's
	// camera may pin/unpin it (lifecycle/retention itself stays admin-only).
	if _, ok := h.eventForUser(w, r, userID, id); !ok {
		return
	}
	var req keepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if _, err := h.events.SetKeepClip(r.Context(), id, req.Keep); err != nil {
		writeError(w, http.StatusInternalServerError, "keep update failed")
		return
	}
	if req.Keep {
		// Detached from the request: pull the clip into the cache so pinning
		// preserves it regardless of Frigate's own recording retention.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if _, err := h.frigate.EnsureCachedClip(ctx, id, h.cfg.ClipsDir()); err != nil {
				h.log.Warn("pin clip cache failed", "event_id", id, "err", err)
			}
		}()
	}
	writeJSON(w, http.StatusOK, keepResponse{EventID: id, Keep: req.Keep})
}

func (h *Handlers) ListEvents(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	q := r.URL.Query()
	f := events.ListFilter{
		Camera: q.Get("camera"),
		Label:  q.Get("label"),
	}
	// Restrict to the caller's accessible cameras unless they see all.
	if allowed, all, err := h.users.AccessibleCameras(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, "access check failed")
		return
	} else if !all {
		f.Cameras = allowed
	}
	if s := q.Get("since"); s != "" {
		if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
			t := time.Unix(ts, 0)
			f.Since = &t
		}
	}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			f.Limit = n
		}
	}
	list, err := h.events.List(r.Context(), f)
	if err != nil {
		h.log.Error("list events failed", "err", err)
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": list})
}

func (h *Handlers) GetEvent(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "event id required")
		return
	}
	ev, ok := h.eventForUser(w, r, userID, id)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// eventPushMetaResp is the just-enough-to-render-a-banner view of an event the
// notification service extension fetches when it receives a privacy-minimal
// relay push (which carries only event_id). The formatting mirrors the MQTT
// dispatcher exactly (events.PushTitle/PushBody) so a relay-mode banner reads
// identically to a direct-mode one.
type eventPushMetaResp struct {
	Title       string `json:"title"`
	Body        string `json:"body"`
	ThreadID    string `json:"thread_id"`
	HasSnapshot bool   `json:"has_snapshot"`
}

// EventPushMeta serves the notification title/body/thread for one event. It sits
// behind MediaMiddleware (accepts the long-lived media token the NSE holds) and
// enforces the caller's per-camera scope via eventForUser, so it exposes nothing
// the caller couldn't already read from the snapshot endpoint.
func (h *Handlers) EventPushMeta(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "event id required")
		return
	}
	ev, ok := h.eventForUser(w, r, userID, id)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, eventPushMetaResp{
		Title:       events.PushTitle(ev.Camera),
		Body:        events.PushBody(ev.Label, ev.SubLabel),
		ThreadID:    ev.Camera,
		HasSnapshot: ev.HasSnapshot,
	})
}

// cameraAccessible reports whether the user may view a specific camera, per their
// role + per-camera scope (admins and unscoped members see all).
func (h *Handlers) cameraAccessible(ctx context.Context, userID, camera string) (bool, error) {
	cams, all, err := h.users.AccessibleCameras(ctx, userID)
	if err != nil {
		return false, err
	}
	if all {
		return true, nil
	}
	for _, c := range cams {
		if c == camera {
			return true, nil
		}
	}
	return false, nil
}

// ensureCameraAccess writes a 403 (or 500) and returns false when the user may
// not access the camera. The camera's existence should be checked separately.
func (h *Handlers) ensureCameraAccess(w http.ResponseWriter, r *http.Request, userID, camera string) bool {
	ok, err := h.cameraAccessible(r.Context(), userID, camera)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access check failed")
		return false
	}
	if !ok {
		writeError(w, http.StatusForbidden, "not authorized for this camera")
		return false
	}
	return true
}

// eventForUser loads an event and verifies the caller may access its camera.
// On any failure it writes the response and returns ok=false.
func (h *Handlers) eventForUser(w http.ResponseWriter, r *http.Request, userID, id string) (*events.Event, bool) {
	ev, err := h.events.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "event lookup failed")
		return nil, false
	}
	if ev == nil {
		writeError(w, http.StatusNotFound, "event not found")
		return nil, false
	}
	ok, err := h.cameraAccessible(r.Context(), userID, ev.Camera)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access check failed")
		return nil, false
	}
	if !ok {
		writeError(w, http.StatusForbidden, "not authorized for this camera")
		return nil, false
	}
	return ev, true
}

type cameraResp struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

func (h *Handlers) ListCameras(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	allowed, all, err := h.users.AccessibleCameras(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access check failed")
		return
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, c := range allowed {
		allowSet[c] = struct{}{}
	}
	cams := h.cameras.List()
	out := make([]cameraResp, 0, len(cams))
	for _, c := range cams {
		if !all {
			if _, ok := allowSet[c.ID]; !ok {
				continue
			}
		}
		out = append(out, cameraResp{ID: c.ID, DisplayName: c.DisplayName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"cameras": out})
}

type cameraLiveResp struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Protocol    string `json:"protocol"`
	WebRTCURL   string `json:"webrtc_url"`
	// HLSURL is the tunnel-friendly fallback (WebRTC needs UDP, which the HTTP
	// tunnel doesn't carry, so it's LAN-only). It embeds a short-lived HLS token
	// so the client can play it directly. Empty if the token couldn't be minted.
	HLSURL string `json:"hls_url,omitempty"`
}

// hlsTokenTTL bounds a live-view session's HLS token. Long enough for a viewing
// session, short enough to limit blast radius if the tokenized URL leaks (logs).
const hlsTokenTTL = time.Hour

func (h *Handlers) CameraLive(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	cam, ok := h.cameras.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "camera not found")
		return
	}
	if !h.ensureCameraAccess(w, r, userID, id) {
		return
	}
	base := strings.TrimRight(h.cfg.PublicBaseURL, "/")
	resp := cameraLiveResp{
		ID:          cam.ID,
		DisplayName: cam.DisplayName,
		Protocol:    "webrtc-whep",
		WebRTCURL:   base + "/api/cameras/" + cam.ID + "/webrtc",
	}
	if h.jwt != nil {
		if tok, _, err := h.jwt.IssueHLS(userID, hlsTokenTTL); err == nil {
			resp.HLSURL = base + "/api/cameras/" + cam.ID + "/hls/index.m3u8?token=" + url.QueryEscape(tok)
		} else {
			h.log.Warn("hls token mint failed", "camera", id, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) CameraWebRTC(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	cam, ok := h.cameras.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "camera not found")
		return
	}
	if !h.ensureCameraAccess(w, r, userID, id) {
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/sdp") {
		writeError(w, http.StatusUnsupportedMediaType, "expected application/sdp")
		return
	}

	offer, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil || len(offer) == 0 {
		writeError(w, http.StatusBadRequest, "missing SDP offer")
		return
	}

	answer, err := h.go2rtc.WHEP(r.Context(), cam.Stream, offer)
	if err != nil {
		h.log.Warn("webrtc exchange failed", "camera", id, "err", err)
		writeError(w, http.StatusBadGateway, "stream unavailable")
		return
	}

	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(answer)
}

// CameraSnapshot proxies Frigate's latest detect-stream frame (`/api/<cam>/latest.jpg`)
// for the multi-camera dashboard. This is a still JPEG off the H.264 substream, so it
// honors the "no H.265 to clients" rule. Optional ?h=<px> scales it down for tiles.
func (h *Handlers) CameraSnapshot(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	cam, ok := h.cameras.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "camera not found")
		return
	}
	if !h.ensureCameraAccess(w, r, userID, id) {
		return
	}
	path := "/api/" + cam.ID + "/latest.jpg"
	if hq := r.URL.Query().Get("h"); hq != "" {
		if n, err := strconv.Atoi(hq); err == nil && n > 0 && n <= 2160 {
			path += "?h=" + strconv.Itoa(n)
		}
	}
	if err := h.frigate.Proxy(path, w, r); err != nil {
		h.log.Warn("camera snapshot proxy failed", "camera", id, "err", err)
		if !errors.Is(err, context.Canceled) {
			writeError(w, http.StatusBadGateway, "snapshot unavailable")
		}
	}
}

func (h *Handlers) EventSnapshot(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "event id required")
		return
	}
	if _, ok := h.eventForUser(w, r, userID, id); !ok {
		return
	}
	if err := h.frigate.Proxy("/api/events/"+id+"/snapshot.jpg", w, r); err != nil {
		h.log.Warn("snapshot proxy failed", "event_id", id, "err", err)
		if !errors.Is(err, context.Canceled) {
			writeError(w, http.StatusBadGateway, "snapshot unavailable")
		}
	}
}

func (h *Handlers) EventClip(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "event id required")
		return
	}
	ev, ok := h.eventForUser(w, r, userID, id)
	if !ok {
		return
	}
	if !ev.HasClip {
		writeError(w, http.StatusNotFound, "clip not available for this event")
		return
	}
	// Serve from a disk cache so AVPlayer gets Range/206 support (Frigate's
	// on-demand clip is a streamed remux with neither Content-Length nor Range).
	if err := h.frigate.ServeCachedClip(w, r, id, h.cfg.ClipsDir()); err != nil {
		h.log.Warn("clip serve failed", "event_id", id, "err", err)
		if !errors.Is(err, context.Canceled) {
			writeError(w, http.StatusBadGateway, "clip unavailable")
		}
	}
}

type createInviteRequest struct {
	Role             string   `json:"role,omitempty"`
	Cameras          []string `json:"cameras,omitempty"`
	Note             string   `json:"note,omitempty"`
	ExpiresInSeconds int64    `json:"expires_in_seconds,omitempty"`
}

type inviteOut struct {
	Code       string     `json:"code"`
	Role       string     `json:"role"`
	Cameras    []string   `json:"cameras"`
	Note       string     `json:"note,omitempty"`
	Pending    bool       `json:"pending"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

func inviteToOut(inv auth.Invite) inviteOut {
	cams := inv.Cameras
	if cams == nil {
		cams = []string{}
	}
	return inviteOut{
		Code:       inv.Code,
		Role:       inv.Role,
		Cameras:    cams,
		Note:       inv.Note,
		Pending:    inv.Pending(),
		CreatedAt:  inv.CreatedAt,
		ExpiresAt:  inv.ExpiresAt,
		ConsumedAt: inv.ConsumedAt,
	}
}

// CreateInvite (admin) mints a single-use invite code with a role + optional
// camera scope. The invitee enters the code on first Sign in with Apple.
func (h *Handlers) CreateInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req createInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = auth.RoleMember
	}
	if role != auth.RoleAdmin && role != auth.RoleMember {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'member'")
		return
	}
	// Reject unknown camera ids so a typo can't silently lock the invitee out.
	for _, c := range req.Cameras {
		if _, ok := h.cameras.Get(c); !ok {
			writeError(w, http.StatusBadRequest, "unknown camera: "+c)
			return
		}
	}
	var expiresAt *time.Time
	if req.ExpiresInSeconds > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInSeconds) * time.Second).Truncate(time.Second).UTC()
		expiresAt = &t
	}

	var inv *auth.Invite
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		code, gerr := auth.NewInviteCode()
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "code generation failed")
			return
		}
		inv, err = h.users.CreateInvite(r.Context(), code, role, req.Cameras, strings.TrimSpace(req.Note), userID, expiresAt)
		if err == nil {
			break
		}
	}
	if err != nil {
		h.log.Error("create invite failed", "err", err)
		writeError(w, http.StatusInternalServerError, "invite create failed")
		return
	}
	writeJSON(w, http.StatusCreated, inviteToOut(*inv))
}

// ListInvites (admin) returns all invites, newest first.
func (h *Handlers) ListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := h.users.ListInvites(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list invites failed")
		return
	}
	out := make([]inviteOut, 0, len(invites))
	for _, inv := range invites {
		out = append(out, inviteToOut(inv))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// DeleteInvite (admin) revokes an invite by code.
func (h *Handlers) DeleteInvite(w http.ResponseWriter, r *http.Request) {
	code := normalizeInviteCode(r.PathValue("code"))
	if code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}
	existed, err := h.users.DeleteInvite(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete invite failed")
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "invite not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
