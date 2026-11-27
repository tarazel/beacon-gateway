package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tarazel/beacon-gateway/internal/auth"
)

func TestRegisterDeviceEnvironment(t *testing.T) {
	h := newTestHandlers(t, nil)

	register := func(body string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/devices", strings.NewReader(body))
		req = req.WithContext(auth.WithUser(req.Context(), "user-1"))
		w := httptest.NewRecorder()
		h.RegisterDevice(w, req)
		return w.Code
	}
	stored := func(token string) sql.NullString {
		t.Helper()
		var env sql.NullString
		if err := h.db.QueryRowContext(context.Background(),
			`SELECT environment FROM devices WHERE apns_token = ?`, token).Scan(&env); err != nil {
			t.Fatalf("read device %s: %v", token, err)
		}
		return env
	}

	// Older clients send no environment: stored as NULL (gateway default applies).
	if code := register(`{"apns_token":"old"}`); code != http.StatusOK {
		t.Fatalf("register without environment: %d", code)
	}
	if env := stored("old"); env.Valid {
		t.Errorf("environment = %q, want NULL", env.String)
	}

	// The same token re-registering with a value fills it in.
	if code := register(`{"apns_token":"old","environment":"sandbox"}`); code != http.StatusOK {
		t.Fatalf("register sandbox: %d", code)
	}
	if env := stored("old"); env.String != "sandbox" {
		t.Errorf("environment = %q, want sandbox", env.String)
	}

	// A later request that omits it keeps the stored value.
	if code := register(`{"apns_token":"old"}`); code != http.StatusOK {
		t.Fatalf("re-register without environment: %d", code)
	}
	if env := stored("old"); env.String != "sandbox" {
		t.Errorf("environment after omit = %q, want sandbox", env.String)
	}

	if code := register(`{"apns_token":"new","environment":"production"}`); code != http.StatusOK {
		t.Fatalf("register production: %d", code)
	}
	if env := stored("new"); env.String != "production" {
		t.Errorf("environment = %q, want production", env.String)
	}

	// Apple's entitlement spelling is not the API's; reject rather than guess.
	if code := register(`{"apns_token":"bad","environment":"development"}`); code != http.StatusBadRequest {
		t.Errorf("invalid environment: status %d, want 400", code)
	}
}
