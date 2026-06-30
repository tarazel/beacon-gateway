package frigate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hydak/beacon-gateway/internal/config"
)

var forwardedRequestHeaders = []string{
	"Range",
	"If-None-Match",
	"If-Modified-Since",
}

var forwardedResponseHeaders = []string{
	"Content-Type",
	"Content-Length",
	"Content-Range",
	"Accept-Ranges",
	"ETag",
	"Last-Modified",
	"Cache-Control",
}

type Client struct {
	cfg       config.Frigate
	streaming *http.Client
}

func NewClient(cfg config.Frigate) *Client {
	return &Client{
		cfg: cfg,
		streaming: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}
}

// Proxy forwards a GET to Frigate, including Range and conditional headers,
// and streams the response (including 206 Partial Content) back to the client.
// Uses no client-side timeout for the body so large clips can stream; the
// caller's request context governs cancellation.
func (c *Client) Proxy(path string, w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	method := r.Method
	if method != http.MethodGet && method != http.MethodHead {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, nil)
	if err != nil {
		return err
	}
	for _, h := range forwardedRequestHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	c.applyAuth(req)

	resp, err := c.streaming.Do(req)
	if err != nil {
		return fmt.Errorf("frigate request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("frigate returned %d", resp.StatusCode)
	}

	for _, h := range forwardedResponseHeaders {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (c *Client) applyAuth(req *http.Request) {
	if c.cfg.CFAccessClientID != "" && c.cfg.CFAccessClientSecret != "" {
		req.Header.Set("CF-Access-Client-Id", c.cfg.CFAccessClientID)
		req.Header.Set("CF-Access-Client-Secret", c.cfg.CFAccessClientSecret)
	}
}

// ServeCachedClip serves event clip <id> with full HTTP Range support.
// Frigate generates clips on-demand as a streamed ffmpeg remux with no
// Content-Length and no Range support, which AVPlayer cannot play. So on the
// first request we download the whole clip to <cacheDir>/<id>.mp4, then serve it
// with http.ServeFile (which provides Range / 206 / Content-Length). Subsequent
// range requests during playback are served straight from disk.
func (c *Client) ServeCachedClip(w http.ResponseWriter, r *http.Request, id, cacheDir string) error {
	cachePath, err := c.EnsureCachedClip(r.Context(), id, cacheDir)
	if err != nil {
		return err
	}
	http.ServeFile(w, r, cachePath)
	return nil
}

// EnsureCachedClip downloads and remuxes event <id>'s clip into
// <cacheDir>/<id>.mp4 if it isn't already cached, returning the cache path. Used
// both by ServeCachedClip and to proactively cache a clip when it gets pinned.
func (c *Client) EnsureCachedClip(ctx context.Context, id, cacheDir string) (string, error) {
	cachePath := filepath.Join(cacheDir, id+".mp4")
	if info, err := os.Stat(cachePath); err != nil || info.Size() == 0 {
		if err := c.cacheClip(ctx, id, cacheDir, cachePath); err != nil {
			return "", err
		}
	}
	return cachePath, nil
}

func (c *Client) cacheClip(ctx context.Context, id, cacheDir, cachePath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/events/"+id+"/clip.mp4", nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)
	resp, err := c.streaming.Do(req)
	if err != nil {
		return fmt.Errorf("frigate clip request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("frigate clip status %d", resp.StatusCode)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}

	// Download the raw clip first. Frigate serves a fragmented MP4 whose moov
	// declares a zero duration, which AVPlayer cannot play.
	raw := cachePath + ".raw"
	f, err := os.Create(raw)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(raw)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(raw)
		return err
	}
	defer os.Remove(raw)

	// Remux into a non-fragmented, faststart MP4 with a real duration; retag
	// hev1 -> hvc1 for AVPlayer. ServeFile then plays it with Range support.
	//
	// Frigate builds the clip by concatenating recording *segments*, which
	// leaves timestamp discontinuities. Plain `-c copy` carried those straight
	// through, so the audio stuttered at every seam and AVPlayer could stop
	// short. The fix, validated against real deimos clips (4608x1728 HEVC,
	// ~19.5fps, no B-frames):
	//   - video: copied (HEVC stays HEVC, lossless). A full re-encode is the
	//     only thing that could drop the duplicate frames at the segment seams,
	//     but re-encoding 4608x1728 HEVC on the CPU per clip is far too slow, so
	//     we don't. Those seams remain as imperceptible micro-hitches; they
	//     don't truncate or corrupt (decode is clean).
	//   - audio: re-encoded to AAC through aresample async=1, which stretches/
	//     pads across the seams to keep it continuous. Copy can't fix this — the
	//     gaps are baked into the packet timestamps. 0:a:0? maps audio only if
	//     present, so a silent clip still remuxes fine.
	//   - timestamps: -fflags +genpts regenerates PTS so the recomputed moov
	//     duration spans the whole clip. (Do NOT add -avoid_negative_ts
	//     make_zero — empirically it shifted the video start ~64ms ahead of the
	//     audio; plain genpts keeps both anchored at 0.)
	tmp := cachePath + ".tmp"
	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-nostdin", "-y",
		"-fflags", "+genpts",
		"-i", raw,
		"-map", "0:v:0", "-map", "0:a:0?",
		"-c:v", "copy",
		"-c:a", "aac", "-b:a", "128k", "-af", "aresample=async=1:first_pts=0",
		"-movflags", "+faststart",
		"-tag:v", "hvc1",
		"-f", "mp4", // temp file ends in .tmp, so force the muxer
		tmp,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("ffmpeg remux clip: %w (%s)", err, lastLine(out))
	}
	return os.Rename(tmp, cachePath)
}

func lastLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 200 {
		s = s[len(s)-200:]
	}
	return s
}
