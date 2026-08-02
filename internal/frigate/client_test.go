package frigate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tarazel/beacon-gateway/internal/config"
)

func TestSearchEvents(t *testing.T) {
	t.Run("success forwards params and preserves order", func(t *testing.T) {
		var gotQuery, gotLimit, gotCameras, gotPath string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotQuery = r.URL.Query().Get("query")
			gotLimit = r.URL.Query().Get("limit")
			gotCameras = r.URL.Query().Get("cameras")
			w.Header().Set("Content-Type", "application/json")
			// Extra fields (search_distance, data, …) must be ignored by the decoder.
			io.WriteString(w, `[
				{"id":"b","camera":"deimos","label":"person","search_distance":0.71},
				{"id":"a","camera":"doorbell","label":"car","search_distance":0.83}
			]`)
		}))
		defer upstream.Close()

		c := NewClient(config.Frigate{BaseURL: upstream.URL})
		res, err := c.SearchEvents(context.Background(), "person at the door", 5, []string{"deimos", "doorbell"})
		if err != nil {
			t.Fatalf("SearchEvents: %v", err)
		}
		if gotPath != "/api/events/search" {
			t.Errorf("path = %q, want /api/events/search", gotPath)
		}
		if gotQuery != "person at the door" {
			t.Errorf("query = %q", gotQuery)
		}
		if gotLimit != "5" {
			t.Errorf("limit = %q, want 5", gotLimit)
		}
		if gotCameras != "deimos,doorbell" {
			t.Errorf("cameras = %q, want deimos,doorbell", gotCameras)
		}
		if len(res) != 2 || res[0].ID != "b" || res[1].ID != "a" {
			t.Fatalf("results not decoded in relevance order: %+v", res)
		}
		if res[0].Camera != "deimos" {
			t.Errorf("camera = %q, want deimos", res[0].Camera)
		}
	})

	t.Run("omits cameras param when scope empty", func(t *testing.T) {
		var hadCameras bool
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hadCameras = r.URL.Query()["cameras"]
			io.WriteString(w, `[]`)
		}))
		defer upstream.Close()

		c := NewClient(config.Frigate{BaseURL: upstream.URL})
		if _, err := c.SearchEvents(context.Background(), "x", 5, nil); err != nil {
			t.Fatalf("SearchEvents: %v", err)
		}
		if hadCameras {
			t.Error("cameras param should be absent when scope is empty (admin/all)")
		}
	})

	t.Run("disabled feature maps to ErrSearchNotEnabled", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"success":false,"message":"Semantic search is not enabled"}`)
		}))
		defer upstream.Close()

		c := NewClient(config.Frigate{BaseURL: upstream.URL})
		_, err := c.SearchEvents(context.Background(), "x", 5, nil)
		if !errors.Is(err, ErrSearchNotEnabled) {
			t.Fatalf("expected ErrSearchNotEnabled, got %v", err)
		}
	})

	t.Run("other error status surfaces as error", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer upstream.Close()

		c := NewClient(config.Frigate{BaseURL: upstream.URL})
		if _, err := c.SearchEvents(context.Background(), "x", 5, nil); err == nil {
			t.Fatal("expected an error on 500")
		} else if errors.Is(err, ErrSearchNotEnabled) {
			t.Fatal("500 should not be treated as not-enabled")
		}
	})
}

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

// TestEnsureCachedClip_SurvivesCallerCancellation is the regression test for
// clips failing to load on cellular: the download+remux job used to run on the
// requesting client's own r.Context(), so a dropped cellular connection (tower
// handoff, brief signal loss, backgrounding — routine on cellular, rare on a
// stable WiFi connection) cancelled it mid-flight, deleting the partial work.
// A retry then restarted the whole expensive job from zero, sometimes looping
// forever on flaky cellular. This verifies a cancelled caller (a) returns
// promptly instead of blocking, and (b) does NOT abort the underlying fetch —
// a second caller for the same id shares the one job already in flight rather
// than triggering a brand new upstream fetch.
func TestEnsureCachedClip_SurvivesCallerCancellation(t *testing.T) {
	var fetches int32
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "partial-clip-bytes")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release // hold the response open to keep the download in flight
	}))
	defer upstream.Close()

	c := NewClient(config.Frigate{BaseURL: upstream.URL})
	dir := t.TempDir()

	// Simulate a caller whose connection has already dropped (cellular hiccup).
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := c.EnsureCachedClip(cancelledCtx, "evt1", dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for a pre-cancelled caller, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("EnsureCachedClip blocked %v on a cancelled caller instead of returning promptly", elapsed)
	}

	// A second, fresh-context caller joins the job the first (now-abandoned)
	// caller kicked off, while it's still held open upstream.
	secondDone := make(chan struct{})
	go func() {
		c.EnsureCachedClip(context.Background(), "evt1", dir) // errors post-download (no ffmpeg in test env); irrelevant here
		close(secondDone)
	}()
	time.Sleep(150 * time.Millisecond) // let the second caller join before we let the job finish
	close(release)

	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second caller never completed")
	}

	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Errorf("expected exactly 1 upstream fetch (job shared via singleflight, not restarted after cancellation), got %d", got)
	}
}

// TestEnsureCachedClip_DedupsConcurrentCallers confirms concurrent callers for
// the same id share a single upstream fetch — the guarantee that keeps a
// pre-warm from racing a user tap on the same clip — while different ids still
// fetch independently.
func TestEnsureCachedClip_DedupsConcurrentCallers(t *testing.T) {
	var fetches int32
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "partial-clip-bytes")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
	}))
	defer upstream.Close()

	c := NewClient(config.Frigate{BaseURL: upstream.URL})
	dir := t.TempDir()

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.EnsureCachedClip(context.Background(), "evt-shared", dir) // errors post-download (no ffmpeg in test env); irrelevant here
		}()
	}
	time.Sleep(150 * time.Millisecond) // let all three join the same in-flight job
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Errorf("expected exactly 1 upstream fetch for 3 concurrent callers of the same id, got %d", got)
	}
}
