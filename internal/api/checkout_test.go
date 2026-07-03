package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hydak/beacon-gateway/internal/auth"
	"github.com/hydak/beacon-gateway/internal/settings"
)

func TestCreateCheckout(t *testing.T) {
	var gotAuth, gotBody, gotPath string
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"url":"https://checkout.stripe.com/c/pay/cs_test_123"}`))
	}))
	defer relay.Close()

	h := newTestHandlers(t, nil)
	h.cfg.Relay.URL = relay.URL
	h.settings = settings.NewStore(h.db)
	if err := h.settings.SetString(context.Background(), settings.KeyRelayInstanceToken, "rk_instance_tok"); err != nil {
		t.Fatalf("seed instance token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/checkout", strings.NewReader(`{"plan":"annual"}`))
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.CreateCheckout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(out.URL, "checkout.stripe.com") {
		t.Fatalf("unexpected url: %s", out.URL)
	}
	if gotPath != "/v1/checkout" {
		t.Errorf("relay path = %q, want /v1/checkout", gotPath)
	}
	if gotAuth != "Bearer rk_instance_tok" {
		t.Errorf("relay auth = %q, want Bearer rk_instance_tok", gotAuth)
	}
	if !strings.Contains(gotBody, `"plan":"annual"`) {
		t.Errorf("relay body = %q, want plan=annual", gotBody)
	}
}

func TestGetSubscription(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscription" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer rk_instance_tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":"pro","sub_status":"active","active":true}`))
	}))
	defer relay.Close()

	h := newTestHandlers(t, nil)
	h.cfg.Relay.URL = relay.URL
	h.settings = settings.NewStore(h.db)
	if err := h.settings.SetString(context.Background(), settings.KeyRelayInstanceToken, "rk_instance_tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/subscription", nil)
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.GetSubscription(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Managed   bool   `json:"managed"`
		Plan      string `json:"plan"`
		SubStatus string `json:"sub_status"`
		Active    bool   `json:"active"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Managed || out.Plan != "pro" || out.SubStatus != "active" || !out.Active {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetSubscription_NotRelayMode(t *testing.T) {
	h := newTestHandlers(t, nil)
	h.settings = settings.NewStore(h.db) // cfg.Relay.URL empty

	req := httptest.NewRequest(http.MethodGet, "/api/subscription", nil)
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.GetSubscription(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var out struct {
		Managed bool `json:"managed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Managed {
		t.Fatal("want managed=false in non-relay mode")
	}
}

func TestCreateCheckout_NotRelayMode(t *testing.T) {
	h := newTestHandlers(t, nil)
	h.settings = settings.NewStore(h.db) // cfg.Relay.URL left empty

	req := httptest.NewRequest(http.MethodPost, "/api/checkout", strings.NewReader(`{}`))
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.CreateCheckout(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when not in relay mode, got %d", w.Code)
	}
}

func TestCreateCheckout_NotRegistered(t *testing.T) {
	h := newTestHandlers(t, nil)
	h.cfg.Relay.URL = "https://relay.example"
	h.settings = settings.NewStore(h.db) // no instance token seeded

	req := httptest.NewRequest(http.MethodPost, "/api/checkout", strings.NewReader(`{}`))
	req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
	w := httptest.NewRecorder()
	h.CreateCheckout(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when not yet registered, got %d", w.Code)
	}
}
