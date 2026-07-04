package apns

import (
	"bytes"
	"encoding/json"
	"testing"
)

// sampleNotification carries content in every field so the tests can assert what
// each payload shape does and does NOT leak.
func sampleNotification() Notification {
	return Notification{
		Title:       "Front Door",
		Body:        "person detected",
		ThreadID:    "front_door",
		EventID:     "evt-123",
		Camera:      "front_door",
		Label:       "person",
		SnapshotURL: "https://beacon.example.com/api/events/evt-123/snapshot",
	}
}

// TestRelayPayloadIsPrivacyMinimal is the load-bearing test for P0.3: the payload
// the gateway hands the relay must carry only the opaque event_id (plus a generic
// alert), never camera/label/snapshot. If this fails, the "relay never sees
// camera/label/image" claim is false.
func TestRelayPayloadIsPrivacyMinimal(t *testing.T) {
	n := sampleNotification()
	raw, err := (&RelayTransport{}).BuildPayload("ios", n)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}

	// event_id must be present so the NSE can fetch the real content.
	var envelope struct {
		EventID string `json:"event_id"`
		APS     struct {
			MutableContent int             `json:"mutable-content"`
			Alert          json.RawMessage `json:"alert"`
		} `json:"aps"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if envelope.EventID != "evt-123" {
		t.Errorf("event_id = %q, want evt-123", envelope.EventID)
	}
	if envelope.APS.MutableContent != 1 {
		t.Error("mutable-content must be 1 so the NSE runs and enriches the banner")
	}
	if len(envelope.APS.Alert) == 0 {
		t.Error("a generic placeholder alert must be present so a banner shows if the NSE fails")
	}

	// The whole point: no event content anywhere in the bytes the relay receives.
	for _, leak := range []string{
		n.Camera, n.Label, n.SnapshotURL,
		"person detected",                 // Body
		"snapshot_url", "camera", "label", // custom keys must be absent
	} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("relay payload leaks %q: %s", leak, raw)
		}
	}
}

// TestDirectPayloadIsRich confirms the self-hosted (own .p8) path keeps the full
// payload — there's no third party to hide it from, and the NSE only attaches the
// image rather than fetching metadata.
func TestDirectPayloadIsRich(t *testing.T) {
	n := sampleNotification()
	raw, err := (&DirectTransport{}).BuildPayload("ios", n)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	for _, want := range []string{n.EventID, n.Camera, n.Label, n.SnapshotURL, "person detected", "Front Door"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("direct payload missing %q: %s", want, raw)
		}
	}
}

// TestAndroidPayloadIsPrivacyMinimal: the FCM data payload carries only event_id,
// never camera/label/snapshot — the same privacy property as the iOS relay path.
func TestAndroidPayloadIsPrivacyMinimal(t *testing.T) {
	n := sampleNotification()
	raw, err := (&RelayTransport{}).BuildPayload("android", n)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("android payload should be a flat string map (FCM data): %v — %s", err, raw)
	}
	if data["event_id"] != n.EventID {
		t.Errorf("event_id = %q, want %q", data["event_id"], n.EventID)
	}
	for _, leak := range []string{n.Camera, n.Label, n.SnapshotURL, "person detected", "aps"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("android payload leaks %q: %s", leak, raw)
		}
	}
}
