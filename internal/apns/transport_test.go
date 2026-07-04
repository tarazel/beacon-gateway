package apns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newStubRelay stands in for the central relay's HTTP API so the gateway's relay
// client can be tested without importing the relay package. It accepts one
// registration secret + one instance token, marks the device token "dead" as
// unregistered, and 401s pushes carrying an unknown bearer token.
func newStubRelay(t *testing.T, regSecret, instanceToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Registration-Secret") != regSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"instance_id":    "inst_test",
			"instance_token": instanceToken,
			"plan":           "trial",
			"sub_status":     "active",
		})
	})
	mux.HandleFunc("/v1/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+instanceToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			DeviceTokens []string `json:"device_tokens"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]map[string]string, len(req.DeviceTokens))
		for i, tk := range req.DeviceTokens {
			if tk == "dead" {
				results[i] = map[string]string{"device_token": tk, "status": StatusUnregistered, "reason": "Unregistered"}
			} else {
				results[i] = map[string]string{"device_token": tk, "status": StatusSent}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	return httptest.NewServer(mux)
}

// TestRelayTransport_EndToEnd exercises the gateway↔relay contract against a stub
// relay: register to get an instance token, then deliver a push and map the
// per-token results. The full relay-side test lives in the beacon-relay repo.
func TestRelayTransport_EndToEnd(t *testing.T) {
	srv := newStubRelay(t, "reg-secret", "rk_test")
	defer srv.Close()
	ctx := context.Background()

	reg, err := RegisterWithRelay(ctx, srv.URL, "reg-secret", srv.Client())
	if err != nil {
		t.Fatalf("RegisterWithRelay: %v", err)
	}
	if reg.InstanceToken != "rk_test" {
		t.Fatalf("instance token = %q, want rk_test", reg.InstanceToken)
	}

	tr := NewRelayTransport(srv.URL, reg.InstanceToken, srv.Client())
	if tr.Name() != "relay" {
		t.Fatalf("Name = %q", tr.Name())
	}

	results, err := tr.Deliver(ctx, "ios", "production", []string{"live", "dead"}, []byte(`{"aps":{"mutable-content":1}}`))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	byToken := map[string]Result{}
	for _, r := range results {
		byToken[r.DeviceToken] = r
	}
	if byToken["live"].Status != StatusSent {
		t.Errorf("live token: want sent, got %q", byToken["live"].Status)
	}
	if byToken["dead"].Status != StatusUnregistered {
		t.Errorf("dead token: want unregistered, got %q", byToken["dead"].Status)
	}
}

func TestRegisterWithRelay_WrongSecret(t *testing.T) {
	srv := newStubRelay(t, "reg-secret", "rk_test")
	defer srv.Close()
	if _, err := RegisterWithRelay(context.Background(), srv.URL, "wrong", srv.Client()); err == nil {
		t.Fatal("expected error registering with a wrong secret")
	}
}

func TestRelayTransport_PushRejectedWhenUnauthorized(t *testing.T) {
	srv := newStubRelay(t, "reg-secret", "rk_test")
	defer srv.Close()
	tr := NewRelayTransport(srv.URL, "rk_bogus", srv.Client())
	if _, err := tr.Deliver(context.Background(), "ios", "production", []string{"x"}, []byte(`{"aps":{}}`)); err == nil {
		t.Fatal("expected error delivering with an unknown instance token")
	}
}

// TestRelayTransport_SubscriptionInactive verifies a 402 from the relay (lapsed
// subscription) surfaces as the ErrSubscriptionInactive sentinel, so the gateway
// can log the dropped-push condition loudly instead of as an opaque HTTP error.
func TestRelayTransport_SubscriptionInactive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"subscription inactive"}`, http.StatusPaymentRequired)
	}))
	defer srv.Close()

	tr := NewRelayTransport(srv.URL, "rk_test", srv.Client())
	_, err := tr.Deliver(context.Background(), "ios", "production", []string{"x"}, []byte(`{"aps":{"mutable-content":1}}`))
	if !errors.Is(err, ErrSubscriptionInactive) {
		t.Fatalf("want ErrSubscriptionInactive, got %v", err)
	}
}
