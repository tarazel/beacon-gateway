package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hydak/beacon-gateway/internal/auth"
	"github.com/hydak/beacon-gateway/internal/cameras"
	"github.com/hydak/beacon-gateway/internal/config"
	"github.com/hydak/beacon-gateway/internal/db"
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
		cfg:     cfg,
		db:      d,
		users:   auth.NewStore(d),
		cameras: cameras.NewRegistry(cams),
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
