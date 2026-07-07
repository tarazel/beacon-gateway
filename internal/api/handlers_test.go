package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
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
	"github.com/tarazel/beacon-gateway/internal/frigate"
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
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
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

// frigateStatsServer returns an httptest server that serves the given /api/stats
// body, and a frigate client pointed at it.
func frigateStatsServer(t *testing.T, statsBody string, status int) *frigate.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stats" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, statsBody)
	}))
	t.Cleanup(srv.Close)
	return frigate.NewClient(config.Frigate{BaseURL: srv.URL})
}

// frigateSearchServer returns a frigate client whose /api/events/search responds
// with the given status+body, recording the `cameras` query param it received in
// *gotCameras (so tests can assert scope was pushed down to Frigate).
func frigateSearchServer(t *testing.T, body string, status int, gotCameras *string) *frigate.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events/search" {
			http.NotFound(w, r)
			return
		}
		if gotCameras != nil {
			*gotCameras = r.URL.Query().Get("cameras")
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return frigate.NewClient(config.Frigate{BaseURL: srv.URL})
}

func decodeSearchIDs(t *testing.T, body io.Reader) []string {
	t.Helper()
	var resp struct {
		Events []struct {
			ID string `json:"id"`
		} `json:"events"`
	}
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		t.Fatalf("decode search response: %v", err)
	}
	ids := make([]string, len(resp.Events))
	for i, e := range resp.Events {
		ids[i] = e.ID
	}
	return ids
}

func TestSearchEvents(t *testing.T) {
	cams := []cameras.Camera{
		{ID: "deimos", DisplayName: "Deimos", Stream: "deimos_sub"},
		{ID: "doorbell", DisplayName: "Doorbell", Stream: "doorbell_sub"},
	}

	t.Run("admin: preserves relevance order, drops unmirrored hits", func(t *testing.T) {
		h := newTestHandlers(t, cams)
		seedEvent(t, h, "evt-b", "deimos", "person", true)
		seedEvent(t, h, "evt-a", "doorbell", "car", true)
		// Frigate ranks b, then a, then "evt-ghost" which the gateway never mirrored.
		h.frigate = frigateSearchServer(t, `[
			{"id":"evt-b","camera":"deimos"},
			{"id":"evt-a","camera":"doorbell"},
			{"id":"evt-ghost","camera":"deimos"}
		]`, http.StatusOK, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/events/search?query=someone+walking", nil)
		req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
		w := httptest.NewRecorder()
		h.SearchEvents(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
		}
		if got := decodeSearchIDs(t, w.Body); len(got) != 2 || got[0] != "evt-b" || got[1] != "evt-a" {
			t.Fatalf("ids = %v, want [evt-b evt-a] (ghost dropped, order preserved)", got)
		}
	})

	t.Run("scoped member: scope pushed to Frigate + out-of-scope hit dropped", func(t *testing.T) {
		h := newTestHandlers(t, cams)
		seedMember(t, h, "member-1", "doorbell")
		seedEvent(t, h, "evt-door", "doorbell", "person", true)
		seedEvent(t, h, "evt-drive", "deimos", "car", true)
		var gotCameras string
		// Frigate (mis)returns a deimos hit too; the handler must still drop it.
		h.frigate = frigateSearchServer(t, `[
			{"id":"evt-drive","camera":"deimos"},
			{"id":"evt-door","camera":"doorbell"}
		]`, http.StatusOK, &gotCameras)

		req := httptest.NewRequest(http.MethodGet, "/api/events/search?query=car", nil)
		req = req.WithContext(auth.WithUser(req.Context(), "member-1"))
		w := httptest.NewRecorder()
		h.SearchEvents(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
		}
		if gotCameras != "doorbell" {
			t.Errorf("cameras pushed to Frigate = %q, want doorbell", gotCameras)
		}
		if got := decodeSearchIDs(t, w.Body); len(got) != 1 || got[0] != "evt-door" {
			t.Fatalf("ids = %v, want [evt-door] (deimos hit dropped)", got)
		}
	})

	t.Run("disabled feature returns 501", func(t *testing.T) {
		h := newTestHandlers(t, cams)
		h.frigate = frigateSearchServer(t, `{"success":false,"message":"Semantic search is not enabled"}`, http.StatusBadRequest, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/events/search?query=x", nil)
		req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
		w := httptest.NewRecorder()
		h.SearchEvents(w, req)

		if w.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", w.Code)
		}
	})

	t.Run("empty query returns 400 without touching Frigate", func(t *testing.T) {
		h := newTestHandlers(t, cams)
		h.frigate = frigateSearchServer(t, `boom`, http.StatusInternalServerError, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/events/search?query=+", nil)
		req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
		w := httptest.NewRecorder()
		h.SearchEvents(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})
}

func TestSystemHealthAggregates(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "deimos", DisplayName: "Deimos", Stream: "deimos_sub"},
		{ID: "doorbell", DisplayName: "Doorbell", Stream: "doorbell_sub"},
	})
	h.frigate = frigateStatsServer(t, `{
		"cameras": {
			"deimos":   {"camera_fps": 20.0, "detection_fps": 5.0, "process_fps": 5.0, "skipped_fps": 0.0},
			"doorbell": {"camera_fps": 15.0, "detection_fps": 5.0, "process_fps": 5.0}
		},
		"detectors": {"coral": {"inference_speed": 8.35}},
		"detection_fps": 10.0,
		"service": {"version": "0.14.1-abc", "uptime": 3600,
			"storage": {"/media/frigate/recordings": {"free": 100000, "total": 500000, "used": 400000, "mount_type": "ext4"}}}
	}`, http.StatusOK)

	req := httptest.NewRequest(http.MethodGet, "/api/system/health", nil)
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.SystemHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp systemHealthResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.Frigate.Reachable {
		t.Error("expected frigate reachable")
	}
	if resp.Frigate.Version != "0.14.1-abc" {
		t.Errorf("version %q", resp.Frigate.Version)
	}
	if resp.Frigate.UptimeSeconds != 3600 {
		t.Errorf("frigate uptime %d", resp.Frigate.UptimeSeconds)
	}
	if len(resp.Frigate.Detectors) != 1 || resp.Frigate.Detectors[0].Name != "coral" ||
		resp.Frigate.Detectors[0].InferenceSpeedMs != 8.35 {
		t.Errorf("detectors %+v", resp.Frigate.Detectors)
	}
	if len(resp.Frigate.Storage) != 1 {
		t.Fatalf("storage %+v", resp.Frigate.Storage)
	}
	// 400000 MB used of 500000 → 80.0%; 400000/1024 ≈ 390.6 GB.
	if resp.Frigate.Storage[0].UsedPct != 80.0 {
		t.Errorf("used_pct %v", resp.Frigate.Storage[0].UsedPct)
	}
	if math.Abs(resp.Frigate.Storage[0].UsedGB-390.6) > 0.05 {
		t.Errorf("used_gb %v", resp.Frigate.Storage[0].UsedGB)
	}

	if len(resp.Cameras) != 2 {
		t.Fatalf("cameras %+v", resp.Cameras)
	}
	var deimos *cameraHealthResp
	for i := range resp.Cameras {
		if resp.Cameras[i].ID == "deimos" {
			deimos = &resp.Cameras[i]
		}
	}
	if deimos == nil || deimos.CameraFPS != 20.0 || deimos.DisplayName != "Deimos" {
		t.Errorf("deimos row %+v", deimos)
	}

	// No relay configured + nil mqtt status in the test harness.
	if resp.Gateway.Push.Transport != "disabled" {
		t.Errorf("push transport %q", resp.Gateway.Push.Transport)
	}
	if resp.Gateway.MQTTConnected {
		t.Error("expected mqtt not connected (nil status)")
	}
}

func TestSystemHealthDegradesWhenFrigateDown(t *testing.T) {
	h := newTestHandlers(t, []cameras.Camera{
		{ID: "deimos", DisplayName: "Deimos", Stream: "deimos_sub"},
	})
	h.frigate = frigateStatsServer(t, "upstream boom", http.StatusInternalServerError)
	h.cameraHealth = stubHealth{offline: map[string]bool{"deimos": true}}

	req := httptest.NewRequest(http.MethodGet, "/api/system/health", nil)
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.SystemHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp systemHealthResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Frigate.Reachable {
		t.Error("expected frigate unreachable")
	}
	// The point of a health view: cameras still render (offline from the monitor)
	// even when Frigate stats are gone.
	if len(resp.Cameras) != 1 || !resp.Cameras[0].Offline || resp.Cameras[0].CameraFPS != 0 {
		t.Errorf("cameras degraded row %+v", resp.Cameras)
	}
}

// stubHealth is a CameraHealth returning canned offline state.
type stubHealth struct{ offline map[string]bool }

func (s stubHealth) Offline(id string) bool { return s.offline[id] }

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
