package apns

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/tarazel/beacon-gateway/internal/db"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// captureTransport records the tokens handed to Deliver (overall and per
// platform) and marks them all sent.
type captureTransport struct {
	delivered  []string
	byPlatform map[string][]string
}

func (c *captureTransport) Name() string { return "capture" }
func (c *captureTransport) BuildPayload(platform string, n Notification) ([]byte, error) {
	return []byte(`{"aps":{"mutable-content":1}}`), nil
}
func (c *captureTransport) Deliver(ctx context.Context, platform, env string, tokens []string, payload []byte) ([]Result, error) {
	if c.byPlatform == nil {
		c.byPlatform = map[string][]string{}
	}
	c.byPlatform[platform] = append(c.byPlatform[platform], tokens...)
	c.delivered = append(c.delivered, tokens...)
	out := make([]Result, len(tokens))
	for i, tk := range tokens {
		out[i] = Result{DeviceToken: tk, Status: StatusSent}
	}
	return out, nil
}

// allowRuler denies exactly the users in `deny`, allowing everyone else.
type allowRuler struct{ deny map[string]bool }

func (a allowRuler) Allows(ctx context.Context, userID string, ev RuleEvent) bool {
	return !a.deny[userID]
}

func TestSendToAll_RulerFiltersPerUser(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	// Two admin users (admins see all cameras), each with one device.
	for _, u := range []struct{ id, tok string }{{"alice", "tok-alice"}, {"bob", "tok-bob"}} {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO users (id, apple_sub, role, created_at) VALUES (?, ?, 'admin', 0)`, u.id, "sub-"+u.id); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		if _, err := d.ExecContext(ctx,
			`INSERT INTO devices (id, user_id, apns_token, last_seen_at, created_at) VALUES (?, ?, ?, 0, 0)`,
			"dev-"+u.id, u.id, u.tok); err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}

	tr := &captureTransport{}
	// Bob's rules filter this event out; Alice's don't.
	sender := NewSender(tr, d, allowRuler{deny: map[string]bool{"bob": true}}, false, discardLogger())

	if err := sender.SendToAll(ctx, Notification{EventID: "e1", Camera: "front", Label: "person"}); err != nil {
		t.Fatalf("SendToAll: %v", err)
	}

	sort.Strings(tr.delivered)
	if len(tr.delivered) != 1 || tr.delivered[0] != "tok-alice" {
		t.Fatalf("expected only tok-alice delivered, got %v", tr.delivered)
	}
}

func TestSendToAll_NilRulerNotifiesEveryone(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, role, created_at) VALUES ('u1', 'sub-u1', 'admin', 0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, apns_token, last_seen_at, created_at) VALUES ('d1', 'u1', 'tok1', 0, 0)`); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	tr := &captureTransport{}
	sender := NewSender(tr, d, nil, false, discardLogger()) // nil ruler = no filtering
	if err := sender.SendToAll(ctx, Notification{EventID: "e1", Camera: "front", Label: "car"}); err != nil {
		t.Fatalf("SendToAll: %v", err)
	}
	if len(tr.delivered) != 1 || tr.delivered[0] != "tok1" {
		t.Fatalf("nil ruler should notify everyone, got %v", tr.delivered)
	}
}

func TestSendToAll_GroupsByPlatform(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, role, created_at) VALUES ('u1', 'sub-u1', 'admin', 0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// One iOS device (platform defaults to 'ios') and one Android device.
	if _, err := d.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, apns_token, last_seen_at, created_at) VALUES ('d-ios', 'u1', 'tok-ios', 0, 0)`); err != nil {
		t.Fatalf("seed ios device: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, apns_token, platform, last_seen_at, created_at) VALUES ('d-and', 'u1', 'tok-and', 'android', 0, 0)`); err != nil {
		t.Fatalf("seed android device: %v", err)
	}

	tr := &captureTransport{}
	sender := NewSender(tr, d, nil, false, discardLogger())
	if err := sender.SendToAll(ctx, Notification{EventID: "e1", Camera: "front", Label: "person"}); err != nil {
		t.Fatalf("SendToAll: %v", err)
	}
	if got := tr.byPlatform["ios"]; len(got) != 1 || got[0] != "tok-ios" {
		t.Errorf("ios bucket = %v, want [tok-ios]", got)
	}
	if got := tr.byPlatform["android"]; len(got) != 1 || got[0] != "tok-and" {
		t.Errorf("android bucket = %v, want [tok-and]", got)
	}
}

// envTransport records which tokens were delivered to which APNs environment and
// can fail one environment's request outright.
type envTransport struct {
	captureTransport
	byEnv   map[string][]string
	failEnv string
}

func (e *envTransport) Deliver(ctx context.Context, platform, env string, tokens []string, payload []byte) ([]Result, error) {
	if env == e.failEnv {
		return nil, errors.New("boom")
	}
	if e.byEnv == nil {
		e.byEnv = map[string][]string{}
	}
	e.byEnv[env] = append(e.byEnv[env], tokens...)
	return e.captureTransport.Deliver(ctx, platform, env, tokens, payload)
}

// seedEnvDevices creates one admin with a sandbox, a production and an
// unreported-environment iOS device.
func seedEnvDevices(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, role, created_at) VALUES ('u1', 'sub-u1', 'admin', 0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := d.ExecContext(ctx, `
		INSERT INTO devices (id, user_id, apns_token, environment, last_seen_at, created_at) VALUES
		('d-sb', 'u1', 'tok-sandbox', 'sandbox', 0, 0),
		('d-pr', 'u1', 'tok-prod', 'production', 0, 0),
		('d-un', 'u1', 'tok-unset', NULL, 0, 0)`); err != nil {
		t.Fatalf("seed devices: %v", err)
	}
	return d
}

func TestSendToAll_RoutesByDeviceEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name           string
		defaultSandbox bool
		want           map[string][]string
	}{
		{"default production", false, map[string][]string{
			"sandbox": {"tok-sandbox"}, "production": {"tok-prod", "tok-unset"}}},
		{"default sandbox", true, map[string][]string{
			"sandbox": {"tok-sandbox", "tok-unset"}, "production": {"tok-prod"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &envTransport{}
			sender := NewSender(tr, seedEnvDevices(t), nil, tc.defaultSandbox, discardLogger())
			if err := sender.SendToAll(context.Background(), Notification{EventID: "e1", Camera: "front"}); err != nil {
				t.Fatalf("SendToAll: %v", err)
			}
			for _, toks := range tr.byEnv {
				sort.Strings(toks)
			}
			if !reflect.DeepEqual(tr.byEnv, tc.want) {
				t.Fatalf("by env = %v, want %v", tr.byEnv, tc.want)
			}
		})
	}
}

func TestSendToAll_FailedBucketDoesNotBlockOthers(t *testing.T) {
	// Map iteration order is random, so repeat to cover the failing bucket going first.
	for i := 0; i < 20; i++ {
		tr := &envTransport{failEnv: "sandbox"}
		sender := NewSender(tr, seedEnvDevices(t), nil, false, discardLogger())
		if err := sender.SendToAll(context.Background(), Notification{EventID: "e1", Camera: "front"}); err == nil {
			t.Fatal("expected the failed bucket to be reported")
		}
		if got := len(tr.byEnv["production"]); got != 2 {
			t.Fatalf("production bucket delivered %d tokens, want 2", got)
		}
	}
}
