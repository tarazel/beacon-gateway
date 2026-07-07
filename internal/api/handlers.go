package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tarazel/beacon-gateway/internal/apns"
	"github.com/tarazel/beacon-gateway/internal/auth"
	"github.com/tarazel/beacon-gateway/internal/cameras"
	"github.com/tarazel/beacon-gateway/internal/config"
	"github.com/tarazel/beacon-gateway/internal/events"
	"github.com/tarazel/beacon-gateway/internal/frigate"
	"github.com/tarazel/beacon-gateway/internal/go2rtc"
	"github.com/tarazel/beacon-gateway/internal/notifrules"
	"github.com/tarazel/beacon-gateway/internal/settings"
)

// CameraHealth reports per-camera offline state (see internal/camhealth). It's
// an interface so handlers stay testable with a nil/stub; nil means "always
// online" (no offline tag emitted).
type CameraHealth interface {
	Offline(id string) bool
}

// MQTTStatus reports the live broker connection state for the health endpoint.
// An interface so handlers stay testable with a nil/stub; nil means "unknown"
// (reported as not connected).
type MQTTStatus interface {
	Connected() bool
}

type Handlers struct {
	cfg          *config.Config
	log          *slog.Logger
	db           *sql.DB
	users        *auth.Store
	jwt          *auth.JWTIssuer
	apple        *auth.AppleVerifier
	google       *auth.GoogleVerifier
	events       *events.Store
	frigate      *frigate.Client
	cameras      *cameras.Registry
	go2rtc       *go2rtc.Client
	settings     *settings.Store
	notifrules   *notifrules.Store
	cameraHealth CameraHealth
	mqtt         MQTTStatus
	startTime    time.Time
	allowlist    map[string]struct{}
	adminEmails  map[string]struct{}
}

// cameraOffline reports whether the camera should be tagged offline, tolerating
// a nil health monitor (tests, or push-disabled builds).
func (h *Handlers) cameraOffline(id string) bool {
	return h.cameraHealth != nil && h.cameraHealth.Offline(id)
}

func NewHandlers(
	cfg *config.Config,
	log *slog.Logger,
	db *sql.DB,
	users *auth.Store,
	jwt *auth.JWTIssuer,
	apple *auth.AppleVerifier,
	google *auth.GoogleVerifier,
	eventStore *events.Store,
	frigateClient *frigate.Client,
	camRegistry *cameras.Registry,
	go2rtcClient *go2rtc.Client,
	settingsStore *settings.Store,
	rulesStore *notifrules.Store,
	cameraHealth CameraHealth,
	mqttStatus MQTTStatus,
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
		cfg:          cfg,
		log:          log,
		db:           db,
		users:        users,
		jwt:          jwt,
		apple:        apple,
		google:       google,
		events:       eventStore,
		frigate:      frigateClient,
		cameras:      camRegistry,
		go2rtc:       go2rtcClient,
		settings:     settingsStore,
		notifrules:   rulesStore,
		cameraHealth: cameraHealth,
		mqtt:         mqttStatus,
		startTime:    time.Now(),
		allowlist:    allow,
		adminEmails:  admins,
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

type googleSignInRequest struct {
	// IDToken is a Google Sign-In ID token (from Credential Manager on Android or
	// the OAuth web/PKCE flow on iOS). id_token is the canonical field name; a
	// legacy identity_token alias is also accepted for symmetry with Apple.
	IDToken       string `json:"id_token"`
	IdentityToken string `json:"identity_token,omitempty"`
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

// appleCallbackScheme is where AppleCallback bounces the identity token so the
// Android app can capture it (matches the intent filter in the app's manifest).
const appleCallbackScheme = "beacon-auth://callback"

// AppleCallback receives Apple's Sign in with Apple web-flow form_post (the Android
// path: response_mode=form_post) and 302-redirects the identity token back to the
// app via its custom scheme. It does NOT verify the token — that happens on
// POST /api/auth/apple — and the app validates the `state` it minted. This is only
// the browser→app handoff Apple's web flow requires.
func (h *Handlers) AppleCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	q := url.Values{}
	if e := r.FormValue("error"); e != "" {
		q.Set("error", e)
	} else {
		q.Set("id_token", r.FormValue("id_token"))
		q.Set("state", r.FormValue("state"))
	}
	http.Redirect(w, r, appleCallbackScheme+"?"+q.Encode(), http.StatusFound)
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
	h.completeProviderSignIn(w, r, providerSignIn{
		provider:      auth.ProviderApple,
		sub:           id.Sub,
		email:         id.Email,
		emailVerified: id.EmailVerified,
		name:          req.Name,
		inviteCode:    req.InviteCode,
		rejectMsg:     "this Apple ID is not authorized — ask the owner for an invite",
		idToken:       req.IdentityToken,
	})
}

func (h *Handlers) GoogleSignIn(w http.ResponseWriter, r *http.Request) {
	if h.google == nil || !h.google.Configured() {
		writeError(w, http.StatusNotImplemented, "google sign-in is not configured on this gateway")
		return
	}
	var req googleSignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "id_token required")
		return
	}
	token := req.IDToken
	if token == "" {
		token = req.IdentityToken
	}
	if token == "" {
		writeError(w, http.StatusBadRequest, "id_token required")
		return
	}
	id, err := h.google.Verify(r.Context(), token)
	if err != nil {
		h.log.Warn("google verify failed", "err", err)
		writeError(w, http.StatusUnauthorized, "invalid google token")
		return
	}
	name := req.Name
	if name == "" {
		name = id.Name
	}
	h.completeProviderSignIn(w, r, providerSignIn{
		provider:      auth.ProviderGoogle,
		sub:           id.Sub,
		email:         id.Email,
		emailVerified: id.EmailVerified,
		name:          name,
		inviteCode:    req.InviteCode,
		rejectMsg:     "this Google account is not authorized — ask the owner for an invite",
		idToken:       token,
	})
}

type providerSignIn struct {
	provider      string
	sub           string
	email         string
	emailVerified bool
	name          string
	inviteCode    string
	rejectMsg     string
	// idToken is the raw provider ID token the app presented. It's forwarded to the
	// push relay to claim this instance on the owner's first admin sign-in (see
	// maybeRegisterRelayAtSignIn) — the account-based, secret-free registration.
	idToken string
}

// completeProviderSignIn is the shared tail of Apple and Google sign-in. It resolves
// the identity to a user in three steps and issues tokens:
//  1. an existing linked (provider, sub) → that user;
//  2. else a verified email matching an existing user → link this identity to them
//     (cross-provider account merge — the same person on a second platform);
//  3. else a brand-new user → gated by the allowlist or a valid invite, then created.
//
// Only step 3 is gated: a returning user (steps 1–2) is already admitted, so an
// invite-only member who later adds a second provider isn't re-challenged.
func (h *Handlers) completeProviderSignIn(w http.ResponseWriter, r *http.Request, in providerSignIn) {
	ctx := r.Context()

	// 1. Known identity.
	user, err := h.users.GetUserByProviderIdentity(ctx, in.provider, in.sub)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	if user != nil {
		h.finishSignIn(w, ctx, in, user)
		return
	}

	// 2. Same person, different provider — link on a verified email match.
	if in.emailVerified && in.email != "" {
		existing, err := h.users.GetUserByEmail(ctx, in.email)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user lookup failed")
			return
		}
		if existing != nil {
			if err := h.users.LinkIdentity(ctx, existing.ID, in.provider, in.sub, in.email); err != nil {
				h.log.Error("link identity failed", "err", err, "user_id", existing.ID, "provider", in.provider)
				writeError(w, http.StatusInternalServerError, "account link failed")
				return
			}
			h.log.Info("linked new identity to existing user", "user_id", existing.ID, "provider", in.provider, "email", in.email)
			h.finishSignIn(w, ctx, in, existing)
			return
		}
	}

	// 3. New user — gate on allowlist or invite.
	allowed := h.emailAllowed(ctx, in.email)
	var invite *auth.Invite
	if code := normalizeInviteCode(in.inviteCode); code != "" {
		if inv, err := h.users.GetInvite(ctx, code); err == nil && inv != nil && inv.Pending() {
			invite = inv
		}
	}
	if !allowed && invite == nil {
		h.log.Warn("sign-in rejected: not allowlisted and no valid invite", "provider", in.provider, "sub", in.sub, "email", in.email)
		writeError(w, http.StatusForbidden, in.rejectMsg)
		return
	}

	role := h.roleForNewUser(ctx, in.email)
	if invite != nil {
		role = invite.Role
	}
	// legacyAppleSub anchors the NOT NULL users.apple_sub column; empty lets the
	// store synthesize "google:<sub>" for non-Apple providers.
	legacyAppleSub := ""
	if in.provider == auth.ProviderApple {
		legacyAppleSub = in.sub
	}
	user, err = h.users.CreateUserWithIdentity(ctx, in.provider, in.sub, legacyAppleSub, in.email, in.name, role)
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
	h.log.Info("new user created", "user_id", user.ID, "role", user.Role, "provider", in.provider, "email", in.email, "via_invite", invite != nil)
	h.finishSignIn(w, ctx, in, user)
}

// finishSignIn registers the gateway with the push relay on the owner's first
// sign-in (best-effort; see maybeRegisterRelayAtSignIn), then issues app tokens.
func (h *Handlers) finishSignIn(w http.ResponseWriter, ctx context.Context, in providerSignIn, u *auth.User) {
	h.maybeRegisterRelayAtSignIn(ctx, in, u)
	h.issueTokens(w, ctx, u.ID)
}

// maybeRegisterRelayAtSignIn claims this instance on the push relay using the
// admin's verified provider ID token — the account-based, secret-free registration
// that makes push work with zero pasted config. It runs only when relay mode is on,
// the signing-in user is an admin (the instance owner), and no instance token is
// stored yet. It's asynchronous and best-effort: it never blocks or fails sign-in,
// and if the relay is unreachable it simply retries on the next admin sign-in. The
// stored token is what buildPushTransport reads on each push.
func (h *Handlers) maybeRegisterRelayAtSignIn(ctx context.Context, in providerSignIn, u *auth.User) {
	if h.cfg.Relay.URL == "" || in.idToken == "" || u == nil || u.Role != auth.RoleAdmin {
		return
	}
	if tok, err := h.settings.GetString(ctx, settings.KeyRelayInstanceToken, ""); err == nil && tok != "" {
		return // already registered
	}
	provider, idToken := in.provider, in.idToken
	go func() {
		// Detached context: the sign-in request's ctx is canceled once it returns.
		bg, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		resp, err := apns.RegisterWithRelay(bg, h.cfg.Relay.URL, provider, idToken, nil)
		if err != nil {
			h.log.Warn("relay registration failed; will retry on next admin sign-in", "err", err)
			return
		}
		if err := h.settings.SetString(bg, settings.KeyRelayInstanceToken, resp.InstanceToken); err != nil {
			h.log.Error("store relay instance token failed", "err", err)
			return
		}
		h.log.Info("registered gateway with relay", "instance_id", resp.InstanceID, "plan", resp.Plan)
	}()
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

// SearchEvents runs a natural-language semantic search over events (Frigate's
// CLIP embeddings) and returns matching events in relevance order, scoped to the
// caller's accessible cameras. Frigate owns the embeddings, so this proxies the
// ranked ids to Frigate and hydrates them from the local store — giving search
// results the exact shape and openability (detail/snapshot/clip all read the
// local store) of the normal events list. Hits the gateway never mirrored are
// dropped. Returns 501 when the Frigate instance has semantic search disabled.
func (h *Handlers) SearchEvents(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if query == "" {
		writeError(w, http.StatusBadRequest, "query required")
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}

	allowed, all, err := h.users.AccessibleCameras(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access check failed")
		return
	}
	// Scope the search itself to the caller's cameras when they don't see all, so
	// a scoped member never even embeds a query against cameras they can't view.
	var scope []string
	if !all {
		if len(allowed) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"events": []events.Event{}})
			return
		}
		scope = allowed
	}

	// Frigate embeds the query text on demand; bound the wait independently of a
	// slow client connection.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	hits, err := h.frigate.SearchEvents(ctx, query, limit, scope)
	if err != nil {
		if errors.Is(err, frigate.ErrSearchNotEnabled) {
			writeError(w, http.StatusNotImplemented, "semantic search is not enabled on this Frigate instance")
			return
		}
		h.log.Error("event search failed", "err", err)
		writeError(w, http.StatusBadGateway, "search failed")
		return
	}

	// Defense in depth: even having passed the scope to Frigate, drop any hit
	// outside the caller's accessible set before hydrating.
	ids := make([]string, 0, len(hits))
	for _, hit := range hits {
		if all || slices.Contains(allowed, hit.Camera) {
			ids = append(ids, hit.ID)
		}
	}
	byID, err := h.events.GetByIDs(r.Context(), ids)
	if err != nil {
		h.log.Error("search hydrate failed", "err", err)
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	// Preserve Frigate's relevance order; drop ids the gateway hasn't mirrored.
	out := make([]events.Event, 0, len(ids))
	for _, id := range ids {
		if ev, ok := byID[id]; ok {
			out = append(out, ev)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
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
	// Offline is true when the gateway has seen no live frames from this camera
	// for the configured debounce window (CAMERA_OFFLINE_AFTER). Clients show an
	// "offline" tag; no push is sent.
	Offline bool `json:"offline"`
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
		out = append(out, cameraResp{ID: c.ID, DisplayName: c.DisplayName, Offline: h.cameraOffline(c.ID)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"cameras": out})
}

// --- System health (admin-only diagnostic surface) ---

type systemHealthResp struct {
	Gateway gatewayHealthResp `json:"gateway"`
	Frigate frigateHealthResp `json:"frigate"`
	Cameras []cameraHealthResp `json:"cameras"`
}

type gatewayHealthResp struct {
	UptimeSeconds int64          `json:"uptime_seconds"`
	MQTTConnected bool           `json:"mqtt_connected"`
	Push          pushHealthResp `json:"push"`
}

type pushHealthResp struct {
	Transport  string `json:"transport"`  // "relay" | "direct" | "disabled"
	Registered bool   `json:"registered"` // relay only: instance token present
}

type frigateHealthResp struct {
	Reachable     bool                `json:"reachable"`
	Version       string              `json:"version,omitempty"`
	UptimeSeconds int64               `json:"uptime_seconds,omitempty"`
	DetectionFPS  float64             `json:"detection_fps"`
	Detectors     []detectorHealthResp `json:"detectors"`
	Storage       []storageHealthResp  `json:"storage"`
}

type detectorHealthResp struct {
	Name             string  `json:"name"`
	InferenceSpeedMs float64 `json:"inference_speed_ms"`
}

type storageHealthResp struct {
	Path    string  `json:"path"`
	UsedGB  float64 `json:"used_gb"`
	TotalGB float64 `json:"total_gb"`
	UsedPct float64 `json:"used_pct"`
}

type cameraHealthResp struct {
	ID           string  `json:"id"`
	DisplayName  string  `json:"display_name"`
	Offline      bool    `json:"offline"`
	CameraFPS    float64 `json:"camera_fps"`
	DetectionFPS float64 `json:"detection_fps"`
	ProcessFPS   float64 `json:"process_fps"`
}

// SystemHealth aggregates gateway, Frigate, and per-camera health into one
// payload for the app's diagnostics screen. Admin-only (owner surface). It
// degrades gracefully: if Frigate's /api/stats is unreachable, frigate.reachable
// is false and cameras still render (offline from the camhealth monitor, FPS 0)
// — the whole point of a health view is to work when things are down.
func (h *Handlers) SystemHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Gateway self-status — derivable without touching Frigate.
	transport := "disabled"
	registered := false
	if h.cfg.Relay.URL != "" {
		transport = "relay"
		if tok, err := h.settings.GetString(ctx, settings.KeyRelayInstanceToken, ""); err == nil && tok != "" {
			registered = true
		}
	} else if h.cfg.APNsConfigured() {
		transport = "direct"
	}
	mqttConnected := h.mqtt != nil && h.mqtt.Connected()

	resp := systemHealthResp{
		Gateway: gatewayHealthResp{
			UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
			MQTTConnected: mqttConnected,
			Push:          pushHealthResp{Transport: transport, Registered: registered},
		},
		Frigate: frigateHealthResp{Detectors: []detectorHealthResp{}, Storage: []storageHealthResp{}},
		Cameras: []cameraHealthResp{},
	}

	// Frigate stats — best effort. On failure, report unreachable and still emit
	// per-camera rows (fps 0) with offline state from the health monitor.
	stats, err := h.frigate.Stats(ctx)
	if err != nil {
		h.log.Warn("system health: frigate stats unavailable", "err", err)
	} else {
		resp.Frigate.Reachable = true
		resp.Frigate.Version = stats.Service.Version
		resp.Frigate.UptimeSeconds = int64(stats.Service.Uptime)
		resp.Frigate.DetectionFPS = stats.DetectionFPS
		for name, d := range stats.Detectors {
			resp.Frigate.Detectors = append(resp.Frigate.Detectors, detectorHealthResp{
				Name:             name,
				InferenceSpeedMs: d.InferenceSpeed,
			})
		}
		sort.Slice(resp.Frigate.Detectors, func(i, j int) bool {
			return resp.Frigate.Detectors[i].Name < resp.Frigate.Detectors[j].Name
		})
		for path, s := range stats.Service.Storage {
			usedGB := s.Used / 1024
			totalGB := s.Total / 1024
			pct := 0.0
			if s.Total > 0 {
				pct = s.Used / s.Total * 100
			}
			resp.Frigate.Storage = append(resp.Frigate.Storage, storageHealthResp{
				Path:    path,
				UsedGB:  math.Round(usedGB*10) / 10,
				TotalGB: math.Round(totalGB*10) / 10,
				UsedPct: math.Round(pct*10) / 10,
			})
		}
		sort.Slice(resp.Frigate.Storage, func(i, j int) bool {
			return resp.Frigate.Storage[i].Path < resp.Frigate.Storage[j].Path
		})
	}

	// Per-camera rows: display name + offline from the gateway, FPS from Frigate
	// stats (keyed by camera id, 0 when stats are unavailable or the camera is down).
	for _, c := range h.cameras.List() {
		row := cameraHealthResp{ID: c.ID, DisplayName: c.DisplayName, Offline: h.cameraOffline(c.ID)}
		if stats != nil {
			if s, ok := stats.Cameras[c.ID]; ok {
				row.CameraFPS = s.CameraFPS
				row.DetectionFPS = s.DetectionFPS
				row.ProcessFPS = s.ProcessFPS
			}
		}
		resp.Cameras = append(resp.Cameras, row)
	}

	writeJSON(w, http.StatusOK, resp)
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
	// Offline mirrors cameraResp.Offline for the live-view screen.
	Offline bool `json:"offline"`
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
		Offline:     h.cameraOffline(cam.ID),
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
