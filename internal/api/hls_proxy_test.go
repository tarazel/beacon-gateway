package api

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tarazel/beacon-gateway/internal/auth"
	"github.com/tarazel/beacon-gateway/internal/cameras"
	"github.com/tarazel/beacon-gateway/internal/go2rtc"
)

const hlsSecret = "rtsp://admin:camera-password@10.0.0.9/stream"

// newHLSProxyFixture wires the real router to a fake go2rtc that serves HLS and,
// like the real one, an admin API that returns camera credentials.
func newHLSProxyFixture(t *testing.T) (get func(target string) (int, string), iss *auth.JWTIssuer, upstream string, hits func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	g := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/stream.m3u8":
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			io.WriteString(w, "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nhls/playlist.m3u8?id=abc\n")
		case "/api/hls/playlist.m3u8":
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			io.WriteString(w, "#EXTM3U\n#EXTINF:1.0,\nsegment.ts?id=abc&n=0\n")
		case "/api/hls/segment.ts":
			io.WriteString(w, "SEGMENT")
		case "/api/hls/redirect.ts":
			http.Redirect(w, r, "/api/config", http.StatusFound)
		default:
			io.WriteString(w, hlsSecret)
		}
	}))
	t.Cleanup(g.Close)

	h := newTestHandlers(t, []cameras.Camera{{ID: "front", Stream: "front_sub"}, {ID: "private", Stream: "private_sub"}})
	h.cfg.Auth.JWTSigningKey = []byte(strings.Repeat("k", 48))
	h.go2rtc = go2rtc.NewClient(g.URL)
	seedMember(t, h, "guest", "front")
	iss = auth.NewJWTIssuer(h.cfg.Auth.JWTSigningKey, 15*time.Minute)
	h.jwt = iss
	router := NewRouter(h, iss, h.users, slog.New(slog.NewTextHandler(io.Discard, nil)))
	get = func(target string) (int, string) {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
		return w.Code, w.Body.String()
	}
	return get, iss, g.URL, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// lastURI returns the last URI line of a playlist.
func lastURI(playlist string) string {
	lines := strings.Fields(strings.TrimSpace(playlist))
	return lines[len(lines)-1]
}

func TestHLSProxyPlaysThrough(t *testing.T) {
	get, iss, _, _ := newHLSProxyFixture(t)
	tok, _, _ := iss.IssueHLS("guest", time.Minute)

	code, master := get("/api/cameras/front/hls/index.m3u8?token=" + tok)
	if code != http.StatusOK {
		t.Fatalf("master playlist: %d %s", code, master)
	}
	code, media := get(lastURI(master))
	if code != http.StatusOK {
		t.Fatalf("media playlist: %d %s", code, media)
	}
	if code, seg := get(lastURI(media)); code != http.StatusOK || seg != "SEGMENT" {
		t.Fatalf("segment: %d %q", code, seg)
	}
}

func TestHLSProxyRejectsUnissuedURLs(t *testing.T) {
	get, iss, upstream, hits := newHLSProxyFixture(t)
	tok, _, _ := iss.IssueHLS("guest", time.Minute)
	_, master := get("/api/cameras/front/hls/index.m3u8?token=" + tok)
	issued, _ := url.Parse(lastURI(master))

	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, target := range []string{
		"/api/config", "/api/streams", "/api/frame.jpeg?src=private_sub",
		"/api/stream.m3u8?src=private_sub", "/api/hls/playlist.m3u8?id=guessed",
	} {
		// Unsigned, and with a genuine signature belonging to a different URL.
		for _, sig := range []string{"", issued.Query().Get("sig")} {
			q := url.Values{"u": {enc(upstream + target)}, "sig": {sig}, "token": {tok}}
			if code, body := get("/api/cameras/front/hls/r?" + q.Encode()); code != http.StatusBadRequest || strings.Contains(body, hlsSecret) {
				t.Errorf("%s (sig %q): status %d, body %q", target, sig, code, body)
			}
		}
	}
	// The master playlist fetch is the only request go2rtc should have seen.
	if got := hits(); len(got) != 1 {
		t.Errorf("go2rtc saw %v, want only the index fetch", got)
	}
}

func TestHLSProxySignatureIsPerCamera(t *testing.T) {
	get, iss, _, _ := newHLSProxyFixture(t)
	owner, _, _ := iss.IssueHLS("user-1", time.Minute) // admin: may watch both
	guest, _, _ := iss.IssueHLS("guest", time.Minute)  // may watch "front" only

	_, private := get("/api/cameras/private/hls/index.m3u8?token=" + owner)
	u, _ := url.Parse(lastURI(private))
	// A URL issued for the other camera, replayed under the guest's own camera.
	q := u.Query()
	q.Set("token", guest)
	if code, _ := get("/api/cameras/front/hls/r?" + q.Encode()); code != http.StatusBadRequest {
		t.Errorf("replayed under another camera: status %d, want 400", code)
	}
	if code, _ := get("/api/cameras/private/hls/r?" + q.Encode()); code != http.StatusForbidden {
		t.Errorf("guest on the other camera: status %d, want 403", code)
	}
}

// Even a signed URL must be an HLS path, and a redirect must not be followed.
func TestHLSProxyPathAndRedirectLimits(t *testing.T) {
	_, _, upstream, _ := newHLSProxyFixture(t)
	client := go2rtc.NewClient(upstream)
	for raw, want := range map[string]bool{
		upstream + "/api/hls/segment.ts?id=a":                       true,
		upstream + "/api/config":                                    false,
		upstream + "/api/hls/../config":                             false,
		upstream + "/api/hls/%2e%2e/config":                         false,
		upstream + "/api/hls":                                       false,
		upstream + "/api/hlsx/segment.ts":                           false,
		"http://example.com/api/hls/segment.ts":                     false,
		strings.Replace(upstream, "//", "//u:p@", 1) + "/api/hls/a": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := client.IsHLSResource(u); got != want {
			t.Errorf("IsHLSResource(%q) = %v, want %v", raw, got, want)
		}
	}
	resp, err := client.GetHLS(t.Context(), upstream+"/api/hls/redirect.ts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("redirect was followed: status %d", resp.StatusCode)
	}
}

func TestHLSRejectsMediaToken(t *testing.T) {
	get, iss, _, _ := newHLSProxyFixture(t)
	media, _, _ := iss.IssueMedia("guest", time.Hour)
	if code, _ := get("/api/cameras/front/hls/index.m3u8?token=" + media); code != http.StatusForbidden {
		t.Errorf("media token on live view: status %d, want 403", code)
	}
}
