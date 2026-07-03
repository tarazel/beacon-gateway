// Package relayclient holds the wire-contract types the gateway needs to talk to
// the central push relay (POST /v1/register, /v1/push, and /v1/checkout). They
// are a hand-copied subset of the relay's own types.
//
// KEEP IN SYNC with the beacon-relay repo (internal/relay/relay.go). The gateway
// only needs the request/response shapes and the per-device status strings, and
// deliberately does NOT import the relay module — that lets the relay stay a
// separate (private) repo while this gateway is open source.
package relayclient

import (
	"encoding/json"
	"time"
)

// Per-device delivery status values. Must match the relay's string values.
const (
	StatusSent         = "sent"
	StatusUnregistered = "unregistered"
	StatusError        = "error"
)

// PushResult is the per-device outcome the relay returns. The gateway prunes its
// own devices table for any "unregistered" result.
type PushResult struct {
	DeviceToken string `json:"device_token"`
	Status      string `json:"status"` // StatusSent | StatusUnregistered | StatusError
	Reason      string `json:"reason,omitempty"`
}

// PushRequest is the body of POST /v1/push.
type PushRequest struct {
	Environment  string          `json:"environment"` // "production" | "sandbox"
	DeviceTokens []string        `json:"device_tokens"`
	Payload      json.RawMessage `json:"payload"`
}

// PushResponse is returned from POST /v1/push.
type PushResponse struct {
	Results []PushResult `json:"results"`
}

// RegisterResponse is returned once from POST /v1/register. instance_token is
// shown exactly once. Plan/SubStatus are plain strings here (the gateway only
// logs them); the relay defines them as typed enums.
type RegisterResponse struct {
	InstanceID    string     `json:"instance_id"`
	InstanceToken string     `json:"instance_token"`
	Plan          string     `json:"plan"`
	SubStatus     string     `json:"sub_status"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// CheckoutRequest is the body of POST /v1/checkout.
type CheckoutRequest struct {
	Plan string `json:"plan"` // "monthly" (default) | "annual"
}

// CheckoutResponse is returned from POST /v1/checkout — the hosted Stripe
// Checkout URL for the app to open in a browser.
type CheckoutResponse struct {
	URL string `json:"url"`
}
