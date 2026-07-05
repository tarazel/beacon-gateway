package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tarazel/beacon-gateway/internal/auth"
	"github.com/tarazel/beacon-gateway/internal/cameras"
	"github.com/tarazel/beacon-gateway/internal/config"
	"github.com/tarazel/beacon-gateway/internal/db"
	"github.com/tarazel/beacon-gateway/internal/events"
	"github.com/tarazel/beacon-gateway/internal/notifrules"
)

// newTestHandlers builds Handlers backed by a real temp SQLite store and seeds
// the test user "user-1" as an admin (so camera-access checks pass by default).
func newTestHandlers(t *testing.T, cams []cameras.Camera) *Handlers {
	t.Helper()
	cfg := &config.Config{
		PublicBaseURL: "https://beacon.tarazel.com",
	}
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, role, created_at) VALUES ('user-1', 'sub-user-1', 'admin', 0)`); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	return &Handlers{
		cfg:        cfg,
		db:         d,
		users:      auth.NewStore(d),
		events:     events.NewStore(d),
		cameras:    cameras.NewRegistry(cams),
		notifrules: notifrules.NewStore(d),
	}
}

// seedEvent inserts a minimal event row for the given camera.
func seedEvent(t *testing.T, h *Handlers, id, camera, label string, hasSnapshot bool) {
	t.Helper()
	snap := 0
	if hasSnapshot {
		snap = 1
	}
	if _, err := h.db.ExecContext(context.Background(),
		`INSERT INTO events (id, camera, label, start_time, top_score, has_snapshot, zones, raw_json, created_at, updated_at)
		 VALUES (?, ?, ?, 0, 0, ?, '[]', '{}', 0, 0)`, id, camera, label, snap); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

// seedMember inserts a member user and optionally scopes them to cameras.
func seedMember(t *testing.T, h *Handlers, id string, cameras ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, role, created_at) VALUES (?, ?, 'member', 0)`, id, "sub-"+id); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if len(cameras) > 0 {
		if err := h.users.SetUserCameras(ctx, id, cameras); err != nil {
			t.Fatalf("scope member: %v", err)
		}
	}
}

func TestCameraLiveReturnsDescriptor(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "front_door", DisplayName: "Front Door", Stream: "front_door_sub"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/cameras/front_door/live", nil)
	req.SetPathValue("id", "front_door")
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()

	h.CameraLive(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp cameraLiveResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.ID != "front_door" {
		t.Errorf("id: %q", resp.ID)
	}
	if resp.DisplayName != "Front Door" {
		t.Errorf("display_name: %q", resp.DisplayName)
	}
	if resp.Protocol != "webrtc-whep" {
		t.Errorf("protocol: %q", resp.Protocol)
	}
	if resp.WebRTCURL != "https://beacon.tarazel.com/api/cameras/front_door/webrtc" {
		t.Errorf("webrtc_url: %q", resp.WebRTCURL)
	}
}

func TestCameraLiveNotFound(t *testing.T) {
	h := newTestHandlers(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/cameras/missing/live", nil)
	req.SetPathValue("id", "missing")
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()

	h.CameraLive(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCameraLiveRequiresAuth(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "front_door", DisplayName: "Front Door", Stream: "front_door_sub"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/cameras/front_door/live", nil)
	req.SetPathValue("id", "front_door")
	w := httptest.NewRecorder()

	h.CameraLive(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCameraLiveScopedMemberForbidden(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "front_door", DisplayName: "Front Door", Stream: "front_door_sub"},
		{ID: "garage", DisplayName: "Garage", Stream: "garage_sub"},
	})
	seedMember(t, h, "member-1", "front_door") // scoped to front_door only

	// In-scope camera -> 200.
	reqOK := httptest.NewRequest(http.MethodGet, "/api/cameras/front_door/live", nil)
	reqOK.SetPathValue("id", "front_door")
	reqOK = reqOK.WithContext(auth.WithUser(reqOK.Context(), "member-1"))
	wOK := httptest.NewRecorder()
	h.CameraLive(wOK, reqOK)
	if wOK.Code != http.StatusOK {
		t.Fatalf("in-scope camera: expected 200, got %d: %s", wOK.Code, wOK.Body.String())
	}

	// Out-of-scope camera -> 403.
	reqNo := httptest.NewRequest(http.MethodGet, "/api/cameras/garage/live", nil)
	reqNo.SetPathValue("id", "garage")
	reqNo = reqNo.WithContext(auth.WithUser(reqNo.Context(), "member-1"))
	wNo := httptest.NewRecorder()
	h.CameraLive(wNo, reqNo)
	if wNo.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope camera: expected 403, got %d: %s", wNo.Code, wNo.Body.String())
	}
}

func TestListCamerasFiltersByScope(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "front_door", DisplayName: "Front Door", Stream: "front_door_sub"},
		{ID: "garage", DisplayName: "Garage", Stream: "garage_sub"},
	})
	seedMember(t, h, "member-1", "garage")

	req := httptest.NewRequest(http.MethodGet, "/api/cameras", nil)
	req = req.WithContext(auth.WithUser(req.Context(), "member-1"))
	w := httptest.NewRecorder()
	h.ListCameras(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Cameras []cameraResp `json:"cameras"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Cameras) != 1 || resp.Cameras[0].ID != "garage" {
		t.Fatalf("scoped member should see only garage, got %+v", resp.Cameras)
	}
}

func TestEventPushMetaReturnsBannerFields(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "front_door", DisplayName: "Front Door", Stream: "front_door_sub"},
	})
	seedEvent(t, h, "evt-1", "front_door", "person", true)

	req := httptest.NewRequest(http.MethodGet, "/api/events/evt-1/push", nil)
	req.SetPathValue("id", "evt-1")
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.EventPushMeta(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp eventPushMetaResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Title != "front_door" {
		t.Errorf("title = %q, want front_door", resp.Title)
	}
	if resp.Body != "person detected" {
		t.Errorf("body = %q, want 'person detected'", resp.Body)
	}
	if resp.ThreadID != "front_door" {
		t.Errorf("thread_id = %q, want front_door", resp.ThreadID)
	}
	if !resp.HasSnapshot {
		t.Error("has_snapshot should be true")
	}
}

// The NSE holds only a media token scoped to the user; the push-metadata
// endpoint must enforce the same per-camera scope as the snapshot endpoint.
func TestEventPushMetaScopedMemberForbidden(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "front_door", DisplayName: "Front Door", Stream: "front_door_sub"},
		{ID: "garage", DisplayName: "Garage", Stream: "garage_sub"},
	})
	seedMember(t, h, "member-1", "front_door") // scoped to front_door only
	seedEvent(t, h, "evt-garage", "garage", "car", true)

	req := httptest.NewRequest(http.MethodGet, "/api/events/evt-garage/push", nil)
	req.SetPathValue("id", "evt-garage")
	req = req.WithContext(auth.WithUser(req.Context(), "member-1"))
	w := httptest.NewRecorder()
	h.EventPushMeta(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope event: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNotificationRulesGetDefaultThenRoundtrip(t *testing.T) {
	h := newTestHandlers(t, nil)

	// GET with no stored rule -> allow-all default.
	reqGet := httptest.NewRequest(http.MethodGet, "/api/notification-rules", nil)
	reqGet = reqGet.WithContext(auth.WithUser(reqGet.Context(), "user-1"))
	wGet := httptest.NewRecorder()
	h.GetNotificationRules(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d: %s", wGet.Code, wGet.Body.String())
	}
	var def notifrules.Rule
	if err := json.Unmarshal(wGet.Body.Bytes(), &def); err != nil {
		t.Fatalf("decode default: %v", err)
	}
	if len(def.Labels) != 0 || def.QuietStartMin != -1 {
		t.Fatalf("expected allow-all default, got %+v", def)
	}

	// PUT with an out-of-range min_score -> server clamps to 1.
	body := `{"labels":["person"," person "],"min_score":5,"cooldown_seconds":60,"quiet_start_min":1320,"quiet_end_min":420}`
	reqPut := httptest.NewRequest(http.MethodPut, "/api/notification-rules", strings.NewReader(body))
	reqPut = reqPut.WithContext(auth.WithUser(reqPut.Context(), "user-1"))
	wPut := httptest.NewRecorder()
	h.PutNotificationRules(wPut, reqPut)
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", wPut.Code, wPut.Body.String())
	}
	var saved notifrules.Rule
	if err := json.Unmarshal(wPut.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode saved: %v", err)
	}
	if len(saved.Labels) != 1 || saved.Labels[0] != "person" {
		t.Errorf("labels not normalized: %v", saved.Labels)
	}
	if saved.MinScore != 1 {
		t.Errorf("min_score not clamped to 1: %v", saved.MinScore)
	}
	if saved.CooldownSeconds != 60 || saved.QuietStartMin != 1320 || saved.QuietEndMin != 420 {
		t.Errorf("roundtrip mismatch: %+v", saved)
	}
}
