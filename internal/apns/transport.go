package apns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"

	"github.com/hydak/beacon-gateway/internal/config"
	relay "github.com/hydak/beacon-gateway/internal/relayclient"
)

// ErrSubscriptionInactive is returned by RelayTransport.Deliver when the relay
// rejects a push with HTTP 402 because this instance's Beacon Pro subscription
// has lapsed (or its trial expired). Sender treats it specially and logs loudly,
// so a household's dropped pushes are never buried in a generic delivery error.
var ErrSubscriptionInactive = errors.New("relay: Beacon Pro subscription inactive")

// Delivery status values, aligned with the relay's so results map 1:1 across
// both transports.
const (
	StatusSent         = relay.StatusSent
	StatusUnregistered = relay.StatusUnregistered
	StatusError        = relay.StatusError
)

// Result is the per-device outcome of a delivery. Unregistered means the gateway
// should prune that device token.
type Result struct {
	DeviceToken string
	Status      string
	Reason      string
}

// Transport delivers an APNs payload to a set of device tokens. The
// device-selection logic lives in Sender, which asks the Transport to render the
// payload (BuildPayload) and then to deliver it (Deliver) — either directly to
// APNs (DirectTransport, for self-hosters with their own .p8) or via the central
// relay (RelayTransport). Rendering is a Transport concern because the relay path
// must be privacy-minimal while the direct path can be rich (see BuildPayload).
type Transport interface {
	// BuildPayload renders a Notification into the APNs payload JSON this
	// transport should send. The two transports intentionally differ:
	//   - DirectTransport signs with the self-hoster's own .p8, so no third party
	//     ever sees the payload — it sends the full rich payload
	//     (title/body/camera/label/snapshot_url) and the NSE just attaches the image.
	//   - RelayTransport forwards through Tarazel's hosted relay, so the payload
	//     must NOT carry event content. It sends a privacy-minimal payload
	//     (mutable-content + event_id + a generic placeholder alert); the on-device
	//     NSE fetches title/body/snapshot from the user's OWN gateway. This is what
	//     makes the advertised "relay never sees camera/label/image" property true.
	// BuildPayload renders the payload for the given platform: an APNs payload for
	// "ios", an FCM `data` map for "android". (Payloads are platform-specific, so
	// SendToAll calls this per platform bucket.)
	BuildPayload(platform string, n Notification) ([]byte, error)
	// Deliver sends payload to deviceTokens for the given platform ("ios"/"android").
	// The relay routes by platform (APNs vs FCM); DirectTransport is iOS-only.
	Deliver(ctx context.Context, platform, environment string, deviceTokens []string, payload []byte) ([]Result, error)
	Name() string
}

// buildRichPayload renders the full payload the gateway sends when it signs
// pushes itself (DirectTransport): title/body/snapshot URL are carried in the
// push so the NSE only has to attach the snapshot image.
func buildRichPayload(n Notification) ([]byte, error) {
	p := payload.NewPayload().
		AlertTitle(n.Title).
		AlertBody(n.Body).
		Sound("default").
		MutableContent().
		ThreadID(n.ThreadID).
		Custom("event_id", n.EventID).
		Custom("camera", n.Camera).
		Custom("label", n.Label)
	if n.SnapshotURL != "" {
		p = p.Custom("snapshot_url", n.SnapshotURL)
	}
	return json.Marshal(p)
}

// buildMinimalPayload renders the privacy-minimal payload the gateway sends
// through the relay: only the opaque event_id plus a generic placeholder alert.
// It deliberately omits camera/label/snapshot_url/thread-id so the relay never
// sees event content. The NSE (triggered by mutable-content) fetches the real
// title/body/snapshot from the user's own gateway keyed by event_id; if that
// fetch fails, the generic alert below still shows a banner.
func buildMinimalPayload(n Notification) ([]byte, error) {
	p := payload.NewPayload().
		AlertTitle("Beacon").
		AlertBody("New activity").
		Sound("default").
		MutableContent().
		Custom("event_id", n.EventID)
	return json.Marshal(p)
}

// buildAndroidDataPayload renders the FCM `data` map for the relay's FCM pusher —
// the Android analog of buildMinimalPayload. Privacy-minimal by the same rule:
// only the opaque event_id (FCM data values must be strings), so the relay never
// sees event content; the Android app fetches title/body/snapshot from its OWN
// gateway keyed by event_id. The FCM pusher wraps this under the message envelope
// with the per-device token + HIGH priority to wake a closed app.
func buildAndroidDataPayload(n Notification) ([]byte, error) {
	return json.Marshal(map[string]string{"event_id": n.EventID})
}

// isUnregistered reports APNs reasons that mean the gateway should prune the
// device token.
func isUnregistered(reason string) bool {
	switch reason {
	case "Unregistered", "BadDeviceToken", "DeviceTokenNotForTopic":
		return true
	}
	return false
}

// --- DirectTransport: sign + send with the gateway's own .p8 ---------------

type DirectTransport struct {
	prod    *apns2.Client
	sandbox *apns2.Client
	topic   string
}

// NewDirectTransport builds a transport that signs with the .p8 at cfg.KeyPath.
// Callers should check config.APNsConfigured() first.
func NewDirectTransport(cfg config.APNs) (*DirectTransport, error) {
	keyBytes, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read apns key: %w", err)
	}
	authKey, err := token.AuthKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse apns key: %w", err)
	}
	tok := &token.Token{AuthKey: authKey, KeyID: cfg.KeyID, TeamID: cfg.TeamID}
	return &DirectTransport{
		prod:    apns2.NewTokenClient(tok).Production(),
		sandbox: apns2.NewTokenClient(tok).Development(),
		topic:   cfg.BundleID,
	}, nil
}

func (d *DirectTransport) Name() string { return "direct" }

// BuildPayload sends the full rich payload — the gateway holds the key, so no
// third party sees the content. DirectTransport is iOS-only (see Deliver).
func (d *DirectTransport) BuildPayload(platform string, n Notification) ([]byte, error) {
	if platform != "" && platform != "ios" {
		return nil, fmt.Errorf("direct transport supports iOS only, not platform %q", platform)
	}
	return buildRichPayload(n)
}

func (d *DirectTransport) Deliver(ctx context.Context, platform, environment string, deviceTokens []string, payloadBytes []byte) ([]Result, error) {
	// DirectTransport signs with the gateway's own APNs .p8 — iOS only. A
	// self-hoster wanting Android push must use the relay (FCM); reject other
	// platforms rather than silently sending a non-APNs token to APNs.
	if platform != "" && platform != "ios" {
		return nil, fmt.Errorf("direct transport supports iOS only, not platform %q", platform)
	}
	client := d.prod
	if environment == "sandbox" {
		client = d.sandbox
	}
	results := make([]Result, 0, len(deviceTokens))
	for _, dt := range deviceTokens {
		resp, err := client.PushWithContext(ctx, &apns2.Notification{
			DeviceToken: dt,
			Topic:       d.topic,
			Payload:     payloadBytes,
		})
		switch {
		case err != nil:
			results = append(results, Result{DeviceToken: dt, Status: StatusError, Reason: err.Error()})
		case resp.Sent():
			results = append(results, Result{DeviceToken: dt, Status: StatusSent})
		case isUnregistered(resp.Reason):
			results = append(results, Result{DeviceToken: dt, Status: StatusUnregistered, Reason: resp.Reason})
		default:
			results = append(results, Result{DeviceToken: dt, Status: StatusError, Reason: resp.Reason})
		}
	}
	return results, nil
}

// --- RelayTransport: forward {tokens, payload} to the central relay ---------

type RelayTransport struct {
	client  *http.Client
	baseURL string
	token   string
}

// NewRelayTransport builds a transport that POSTs to the relay's /v1/push using
// the gateway's instance token.
func NewRelayTransport(baseURL, instanceToken string, client *http.Client) *RelayTransport {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &RelayTransport{
		client:  client,
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   instanceToken,
	}
}

func (r *RelayTransport) Name() string { return "relay" }

// BuildPayload sends the privacy-minimal payload (event_id only), shaped per
// platform: an APNs payload for iOS, an FCM `data` map for Android. The relay
// forwards it verbatim and never sees camera/label/snapshot; the on-device app
// fetches those from the user's own gateway.
func (r *RelayTransport) BuildPayload(platform string, n Notification) ([]byte, error) {
	if platform == "android" {
		return buildAndroidDataPayload(n)
	}
	return buildMinimalPayload(n)
}

func (r *RelayTransport) Deliver(ctx context.Context, platform, environment string, deviceTokens []string, payloadBytes []byte) ([]Result, error) {
	reqBody := relay.PushRequest{
		Environment:  environment,
		Platform:     platform,
		DeviceTokens: deviceTokens,
		Payload:      json.RawMessage(payloadBytes),
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal relay push: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/v1/push", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("relay push request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 402 = this instance's subscription lapsed. Surface it distinctly so the
		// gateway can log it loudly rather than as an opaque "returned 402".
		if resp.StatusCode == http.StatusPaymentRequired {
			return nil, ErrSubscriptionInactive
		}
		return nil, fmt.Errorf("relay push returned %d", resp.StatusCode)
	}
	var out relay.PushResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode relay push response: %w", err)
	}
	results := make([]Result, len(out.Results))
	for i, pr := range out.Results {
		results[i] = Result{DeviceToken: pr.DeviceToken, Status: pr.Status, Reason: pr.Reason}
	}
	return results, nil
}

// RegisterWithRelay performs the gateway's first-boot registration, returning
// the relay's response (whose InstanceToken the caller persists).
func RegisterWithRelay(ctx context.Context, baseURL, registrationSecret string, client *http.Client) (*relay.RegisterResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/register", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Registration-Secret", registrationSecret)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("relay register request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("relay register returned %d", resp.StatusCode)
	}
	var out relay.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode relay register response: %w", err)
	}
	return &out, nil
}

// CheckoutWithRelay asks the relay to create a Stripe Checkout Session for this
// instance (authenticated by its instance token) and returns the hosted-checkout
// URL for the app to open. Only meaningful in relay mode.
func CheckoutWithRelay(ctx context.Context, baseURL, instanceToken, plan string, client *http.Client) (*relay.CheckoutResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	buf, err := json.Marshal(relay.CheckoutRequest{Plan: plan})
	if err != nil {
		return nil, fmt.Errorf("marshal relay checkout: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/checkout", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+instanceToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("relay checkout request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("relay checkout returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out relay.CheckoutResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode relay checkout response: %w", err)
	}
	return &out, nil
}

// SubscriptionFromRelay fetches this instance's entitlement (plan/status/active)
// from the relay, authenticated by the instance token.
func SubscriptionFromRelay(ctx context.Context, baseURL, instanceToken string, client *http.Client) (*relay.SubscriptionResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/v1/subscription", nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+instanceToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("relay subscription request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("relay subscription returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out relay.SubscriptionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode relay subscription response: %w", err)
	}
	return &out, nil
}
