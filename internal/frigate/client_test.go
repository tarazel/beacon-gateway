package frigate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tarazel/beacon-gateway/internal/config"
)

func TestProxyForwardsRangeAndCFHeaders(t *testing.T) {
	var gotRange, gotCFID, gotCFSecret string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		gotCFID = r.Header.Get("CF-Access-Client-Id")
		gotCFSecret = r.Header.Get("CF-Access-Client-Secret")

		if r.Header.Get("Range") != "" {
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 0-99/1000")
			w.Header().Set("Accept-Ranges", "bytes")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(strings.Repeat("x", 100)))
			return
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("full body"))
	}))
	defer upstream.Close()

	c := NewClient(config.Frigate{
		BaseURL:              upstream.URL,
		CFAccessClientID:     "id-123",
		CFAccessClientSecret: "secret-abc",
	})

	t.Run("range request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/events/x/clip.mp4", nil)
		req.Header.Set("Range", "bytes=0-99")
		w := httptest.NewRecorder()

		if err := c.Proxy("/api/events/x/clip.mp4", w, req); err != nil {
			t.Fatalf("proxy: %v", err)
		}

		if w.Code != http.StatusPartialContent {
			t.Errorf("expected 206, got %d", w.Code)
		}
		if gotRange != "bytes=0-99" {
			t.Errorf("Range not forwarded, got %q", gotRange)
		}
		if gotCFID != "id-123" || gotCFSecret != "secret-abc" {
			t.Errorf("CF-Access headers not applied: id=%q secret=%q", gotCFID, gotCFSecret)
		}
		if got := w.Header().Get("Content-Range"); got != "bytes 0-99/1000" {
			t.Errorf("Content-Range not forwarded, got %q", got)
		}
		if got := w.Header().Get("Accept-Ranges"); got != "bytes" {
			t.Errorf("Accept-Ranges not forwarded, got %q", got)
		}
		if got := w.Body.Len(); got != 100 {
			t.Errorf("expected 100 bytes, got %d", got)
		}
	})

	t.Run("full request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/events/x/clip.mp4", nil)
		w := httptest.NewRecorder()

		if err := c.Proxy("/api/events/x/clip.mp4", w, req); err != nil {
			t.Fatalf("proxy: %v", err)
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		body, _ := io.ReadAll(w.Body)
		if string(body) != "full body" {
			t.Errorf("body mismatch: %q", body)
		}
	})
}

func TestProxyHeadMethodOmitsBody(t *testing.T) {
	var gotMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", "1234")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not be sent on HEAD"))
	}))
	defer upstream.Close()

	c := NewClient(config.Frigate{BaseURL: upstream.URL})

	req := httptest.NewRequest(http.MethodHead, "/api/events/x/clip.mp4", nil)
	w := httptest.NewRecorder()
	if err := c.Proxy("/api/events/x/clip.mp4", w, req); err != nil {
		t.Fatalf("proxy: %v", err)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD response should have empty body, got %d bytes", w.Body.Len())
	}
	if got := w.Header().Get("Content-Length"); got != "1234" {
		t.Errorf("Content-Length not forwarded on HEAD, got %q", got)
	}
	if gotMethod != http.MethodHead {
		t.Errorf("upstream method should be HEAD, got %q", gotMethod)
	}
}

// TestEnsureCachedClip_FastPathSkipsFetch verifies an already-cached clip is
// returned without touching Frigate (the pre-warm / serve fast path). The client
// points at a server that fails any request, so a fetch here would error.
func TestEnsureCachedClip_FastPathSkipsFetch(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected fetch for an already-cached clip: %s", r.URL.Path)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failing.Close()

	c := NewClient(config.Frigate{BaseURL: failing.URL})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evt1.mp4"), []byte("cached-bytes"), 0o644); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	path, err := c.EnsureCachedClip(context.Background(), "evt1", dir)
	if err != nil {
		t.Fatalf("EnsureCachedClip: %v", err)
	}
	if path != filepath.Join(dir, "evt1.mp4") {
		t.Fatalf("unexpected path: %s", path)
	}
}

// TestLockClip_SerializesSameID confirms the per-id lock is mutually exclusive
// for one id but independent across ids — the guarantee that keeps a pre-warm
// from racing a user tap on the same clip.
func TestLockClip_SerializesSameID(t *testing.T) {
	c := NewClient(config.Frigate{})

	unlock := c.lockClip("a")
	acquired := make(chan struct{})
	go func() {
		u2 := c.lockClip("a") // must block until unlock() below
		close(acquired)
		u2()
	}()
	select {
	case <-acquired:
		t.Fatal("second lock on same id acquired while first was held")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("second lock never acquired after release")
	}

	// A different id is not blocked by a held lock.
	held := c.lockClip("b")
	done := make(chan struct{})
	go func() { u := c.lockClip("c"); u(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock on a different id should not block")
	}
	held()
}
