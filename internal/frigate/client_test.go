package frigate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hydak/beacon-gateway/internal/config"
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
