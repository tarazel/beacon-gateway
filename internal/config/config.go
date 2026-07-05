package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tarazel/beacon-gateway/internal/cameras"
)

type Config struct {
	HTTPAddr      string
	PublicBaseURL string
	DBPath        string
	LogLevel      string

	MQTT MQTT

	Frigate Frigate

	CameraHealth CameraHealth

	Go2RTC Go2RTC

	Auth Auth

	APNs APNs

	Relay Relay

	Cameras []cameras.Camera

	DevMode bool
}

type Go2RTC struct {
	BaseURL string
}

func (c *Config) PublicSnapshotURL(eventID string) string {
	return strings.TrimRight(c.PublicBaseURL, "/") + "/api/events/" + eventID + "/snapshot"
}

// ClipsDir is the on-disk cache directory for remuxed clips, kept alongside the
// SQLite DB. Both the clip handler and the cache pruner derive it from here.
func (c *Config) ClipsDir() string {
	return filepath.Join(filepath.Dir(c.DBPath), "clips")
}

type MQTT struct {
	Broker        string
	ClientID      string
	Username      string
	Password      string
	EventsTopic   string
	ReconnectWait time.Duration
}

type Frigate struct {
	BaseURL              string
	CFAccessClientID     string
	CFAccessClientSecret string
}

// CameraHealth tunes the offline-detection monitor. PollInterval is how often
// the gateway samples Frigate's per-camera frame rate; OfflineAfter is how long
// a camera must report no frames before it's flagged offline (the debounce that
// keeps a flapping camera from toggling the tag).
type CameraHealth struct {
	PollInterval time.Duration
	OfflineAfter time.Duration
}

type Auth struct {
	JWTSigningKey   []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// MediaTokenTTL is the lifetime of the long-lived, media-scoped token the
	// notification service extension uses to fetch snapshots (it can't refresh).
	MediaTokenTTL time.Duration
	AppleClientID string
	// AppleAllowedAudiences are additional accepted `aud` values beyond
	// AppleClientID — e.g. the Apple Services ID used by the Android
	// Sign-in-with-Apple web flow. Comma-separated in APPLE_ALLOWED_AUDIENCES.
	AppleAllowedAudiences []string
	// GoogleClientID is the primary accepted `aud` for Google Sign-In ID tokens
	// (typically the Web/server OAuth client id the Android Credential Manager
	// flow uses). Empty disables Google sign-in.
	GoogleClientID string
	// GoogleAllowedAudiences are additional accepted `aud` values beyond
	// GoogleClientID — e.g. the iOS OAuth client id. Comma-separated in
	// GOOGLE_ALLOWED_AUDIENCES.
	GoogleAllowedAudiences []string
	AppleAllowedEmails     []string
	// AdminEmails are promoted to the 'admin' role on sign-in. Independent of the
	// first-user bootstrap (which makes whoever signs in first the owner/admin).
	AdminEmails []string
}

// Relay configures the gateway's use of the central push relay. When URL is set
// the gateway sends pushes through the relay (the hosted/paid path) instead of
// signing with its own .p8 directly. RegistrationSecret is used once, on first
// boot, to register with the relay and obtain an instance token (then stored in
// the settings table).
type Relay struct {
	URL                string
	RegistrationSecret string
}

// DefaultRelayURL is Tarazel's hosted push relay. It ships as the default so push
// works out of the box (Beacon Pro): a fresh gateway registers with it on the
// owner's first sign-in — nothing to paste. Self-hosters who want to stay fully
// independent set RELAY_URL to "off" (or "none"/"direct"/"") to disable the relay
// and sign push themselves with their own APNs .p8 (DirectTransport).
const DefaultRelayURL = "https://relay.tarazel.com"

// relayURL resolves RELAY_URL: unset → the hosted relay default; an explicit
// off/none/direct/"" → disabled (empty, direct mode); anything else → that URL.
func relayURL() string {
	v, ok := os.LookupEnv("RELAY_URL")
	if !ok {
		return DefaultRelayURL
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "none", "direct", "disabled":
		return ""
	}
	return strings.TrimSpace(v)
}

type APNs struct {
	KeyPath    string
	KeyID      string
	TeamID     string
	BundleID   string
	UseSandbox bool
}

func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:      getEnv("HTTP_ADDR", ":8080"),
		PublicBaseURL: getEnv("PUBLIC_BASE_URL", "https://beacon.tarazel.com"),
		DBPath:        getEnv("DB_PATH", "data/beacon.db"),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		DevMode:       getBool("DEV_MODE", false),
		MQTT: MQTT{
			Broker:        getEnv("MQTT_BROKER", "tcp://localhost:1883"),
			ClientID:      getEnv("MQTT_CLIENT_ID", "beacon-gateway"),
			Username:      os.Getenv("MQTT_USERNAME"),
			Password:      os.Getenv("MQTT_PASSWORD"),
			EventsTopic:   getEnv("MQTT_EVENTS_TOPIC", "frigate/events"),
			ReconnectWait: 5 * time.Second,
		},
		Frigate: Frigate{
			BaseURL:              getEnv("FRIGATE_BASE_URL", "https://frigate.hydak.org"),
			CFAccessClientID:     os.Getenv("CF_ACCESS_CLIENT_ID"),
			CFAccessClientSecret: os.Getenv("CF_ACCESS_CLIENT_SECRET"),
		},
		CameraHealth: CameraHealth{
			PollInterval: getDuration("CAMERA_HEALTH_POLL_INTERVAL", 30*time.Second),
			OfflineAfter: getDuration("CAMERA_OFFLINE_AFTER", 120*time.Second),
		},
		Go2RTC: Go2RTC{
			BaseURL: getEnv("GO2RTC_BASE_URL", "http://localhost:1984"),
		},
		Auth: Auth{
			JWTSigningKey:          []byte(os.Getenv("JWT_SIGNING_KEY")),
			AccessTokenTTL:         getDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL:        getDuration("REFRESH_TOKEN_TTL", 90*24*time.Hour),
			MediaTokenTTL:          getDuration("MEDIA_TOKEN_TTL", 30*24*time.Hour),
			AppleClientID:          os.Getenv("APPLE_CLIENT_ID"),
			AppleAllowedAudiences:  splitCSV(os.Getenv("APPLE_ALLOWED_AUDIENCES")),
			GoogleClientID:         os.Getenv("GOOGLE_CLIENT_ID"),
			GoogleAllowedAudiences: splitCSV(os.Getenv("GOOGLE_ALLOWED_AUDIENCES")),
			AppleAllowedEmails:     splitCSV(os.Getenv("APPLE_ALLOWED_EMAILS")),
			AdminEmails:            splitCSV(os.Getenv("ADMIN_EMAILS")),
		},
		APNs: APNs{
			KeyPath:    os.Getenv("APNS_KEY_PATH"),
			KeyID:      os.Getenv("APNS_KEY_ID"),
			TeamID:     os.Getenv("APNS_TEAM_ID"),
			BundleID:   os.Getenv("APNS_BUNDLE_ID"),
			UseSandbox: getBool("APNS_USE_SANDBOX", true),
		},
		Relay: Relay{
			URL:                relayURL(),
			RegistrationSecret: os.Getenv("RELAY_REGISTRATION_SECRET"),
		},
	}

	cams, err := loadCameras(os.Getenv("CAMERAS_JSON"))
	if err != nil {
		return nil, err
	}
	c.Cameras = cams

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func loadCameras(raw string) ([]cameras.Camera, error) {
	if raw == "" {
		return nil, nil
	}
	var out []cameras.Camera
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("CAMERAS_JSON: %w", err)
	}
	return out, nil
}

func (c *Config) validate() error {
	if c.DevMode {
		return nil
	}
	var problems []string
	if len(c.Auth.JWTSigningKey) < 32 {
		problems = append(problems, "JWT_SIGNING_KEY must be at least 32 bytes (set DEV_MODE=true to bypass)")
	}
	if c.Auth.AppleClientID == "" {
		problems = append(problems, "APPLE_CLIENT_ID required")
	}
	if len(problems) > 0 {
		return errors.New("config: " + strings.Join(problems, "; "))
	}
	return nil
}

func (c *Config) APNsConfigured() bool {
	return c.APNs.KeyPath != "" && c.APNs.KeyID != "" && c.APNs.TeamID != "" && c.APNs.BundleID != ""
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid duration for %s=%q, using default %s\n", key, v, def)
		return def
	}
	return d
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
