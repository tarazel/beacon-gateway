package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/hydak/beacon-gateway/internal/apns"
	"github.com/hydak/beacon-gateway/internal/settings"
)

type checkoutRequest struct {
	Plan string `json:"plan"` // "monthly" (default) | "annual"
}

// CreateCheckout (admin-only) proxies a subscription-checkout request to the
// central relay using this gateway's instance token, returning the hosted Stripe
// Checkout URL for the app to open.
//
// The subscription entitles the whole instance (household), so only an admin can
// start it. Billing exists only in relay mode — a gateway signing with its own
// .p8 (the free/self-hosted tier) has no relay to sell through.
func (h *Handlers) CreateCheckout(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Relay.URL == "" {
		writeError(w, http.StatusServiceUnavailable, "billing unavailable: gateway not in relay mode")
		return
	}

	var req checkoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	instanceToken, err := h.settings.GetString(r.Context(), settings.KeyRelayInstanceToken, "")
	if err != nil {
		h.log.Error("checkout: read instance token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if instanceToken == "" {
		writeError(w, http.StatusServiceUnavailable, "gateway not registered with relay yet")
		return
	}

	resp, err := apns.CheckoutWithRelay(r.Context(), h.cfg.Relay.URL, instanceToken, req.Plan, nil)
	if err != nil {
		h.log.Error("checkout: relay call failed", "err", err)
		writeError(w, http.StatusBadGateway, "checkout unavailable")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// subscriptionResponse is the app-facing shape for GET /api/subscription.
// Managed is false when this gateway isn't in relay mode (the free/self-hosted
// tier has no subscription), so the app can hide the subscription UI entirely.
type subscriptionResponse struct {
	Managed   bool       `json:"managed"`
	Plan      string     `json:"plan,omitempty"`
	SubStatus string     `json:"sub_status,omitempty"`
	Active    bool       `json:"active"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// GetSubscription reports this household's Beacon Pro status by querying the
// relay with the gateway's instance token. Available to any authenticated user
// (status is household-level, not sensitive); the upgrade action stays admin-only.
func (h *Handlers) GetSubscription(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Relay.URL == "" {
		writeJSON(w, http.StatusOK, subscriptionResponse{Managed: false})
		return
	}
	instanceToken, err := h.settings.GetString(r.Context(), settings.KeyRelayInstanceToken, "")
	if err != nil {
		h.log.Error("subscription: read instance token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if instanceToken == "" {
		// Relay mode but not registered yet — managed, status not yet known.
		writeJSON(w, http.StatusOK, subscriptionResponse{Managed: true, SubStatus: "unknown"})
		return
	}
	sub, err := apns.SubscriptionFromRelay(r.Context(), h.cfg.Relay.URL, instanceToken, nil)
	if err != nil {
		h.log.Error("subscription: relay call failed", "err", err)
		writeError(w, http.StatusBadGateway, "subscription status unavailable")
		return
	}
	writeJSON(w, http.StatusOK, subscriptionResponse{
		Managed:   true,
		Plan:      sub.Plan,
		SubStatus: sub.SubStatus,
		Active:    sub.Active,
		ExpiresAt: sub.ExpiresAt,
	})
}
