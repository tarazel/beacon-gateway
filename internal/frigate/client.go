package frigate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tarazel/beacon-gateway/internal/config"
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

	// Per-event locks serialize concurrent clip caching for the same id (e.g. a
	// background pre-warm racing a user tapping the push), so ffmpeg never runs
	// twice against the same temp files. Different ids still cache concurrently.
	clipMu    sync.Mutex
	clipLocks map[string]*sync.Mutex
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
		clipLocks: make(map[string]*sync.Mutex),
	}
}

// lockClip acquires the per-id clip lock and returns a release func. Callers must
// defer the returned func. The lock is kept in the map after release (bounded by
// the number of distinct events cached this process lifetime — small).
func (c *Client) lockClip(id string) func() {
	c.clipMu.Lock()
	m, ok := c.clipLocks[id]
	if !ok {
		m = &sync.Mutex{}
		c.clipLocks[id] = m
	}
	c.clipMu.Unlock()
	m.Lock()
	return m.Unlock
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

// CameraFPS fetches Frigate's /api/stats and returns each camera's current
// source frame rate (camera_fps), keyed by Frigate camera id. A camera reporting
// 0 has no live frames — ffmpeg has crashed, the RTSP stream is unreachable, or
// the camera is down. The camera-health monitor polls this to flag offline
// cameras. Uses the caller's context for cancellation/timeout.
func (c *Client) CameraFPS(ctx context.Context) (map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/stats", nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)

	resp, err := c.streaming.Do(req)
	if err != nil {
		return nil, fmt.Errorf("frigate stats: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("frigate stats status %d", resp.StatusCode)
	}

	var stats struct {
		Cameras map[string]struct {
			CameraFPS float64 `json:"camera_fps"`
		} `json:"cameras"`
	}
	// Cap the read: /api/stats is a few KB, and this runs on a timer.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&stats); err != nil {
		return nil, fmt.Errorf("frigate stats decode: %w", err)
	}
	out := make(map[string]float64, len(stats.Cameras))
	for name, s := range stats.Cameras {
		out[name] = s.CameraFPS
	}
	return out, nil
}

// Stats is the subset of Frigate's /api/stats surfaced by the system-health
// endpoint: per-camera frame rates, detector inference speed, storage usage,
// plus Frigate's version and uptime. Storage figures are in MB (Frigate's unit).
type Stats struct {
	Cameras      map[string]CameraStat   `json:"cameras"`
	Detectors    map[string]DetectorStat `json:"detectors"`
	DetectionFPS float64                 `json:"detection_fps"`
	Service      ServiceStat             `json:"service"`
}

type CameraStat struct {
	CameraFPS    float64 `json:"camera_fps"`
	DetectionFPS float64 `json:"detection_fps"`
	ProcessFPS   float64 `json:"process_fps"`
	SkippedFPS   float64 `json:"skipped_fps"`
}

type DetectorStat struct {
	InferenceSpeed float64 `json:"inference_speed"` // milliseconds
}

type ServiceStat struct {
	Version string                 `json:"version"`
	Uptime  float64                `json:"uptime"` // seconds
	Storage map[string]StorageStat `json:"storage"`
}

type StorageStat struct {
	Free      float64 `json:"free"`  // MB
	Total     float64 `json:"total"` // MB
	Used      float64 `json:"used"`  // MB
	MountType string  `json:"mount_type"`
}

// Stats fetches and parses Frigate's /api/stats for the health endpoint. Unlike
// CameraFPS (called on a timer, so kept minimal), this is on-demand and returns
// the richer payload. Uses the caller's context for cancellation/timeout.
func (c *Client) Stats(ctx context.Context) (*Stats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/stats", nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)

	resp, err := c.streaming.Do(req)
	if err != nil {
		return nil, fmt.Errorf("frigate stats: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("frigate stats status %d", resp.StatusCode)
	}

	var stats Stats
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&stats); err != nil {
		return nil, fmt.Errorf("frigate stats decode: %w", err)
	}
	return &stats, nil
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
	// Fast path: already cached, no lock needed.
	if info, err := os.Stat(cachePath); err == nil && info.Size() > 0 {
		return cachePath, nil
	}
	// Serialize concurrent cachers of this id, then re-check: another caller may
	// have finished the remux while we waited for the lock.
	unlock := c.lockClip(id)
	defer unlock()
	if info, err := os.Stat(cachePath); err == nil && info.Size() > 0 {
		return cachePath, nil
	}
	if err := c.cacheClip(ctx, id, cacheDir, cachePath); err != nil {
		return "", err
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
	//   - codec tag: only HEVC needs the hev1 -> hvc1 retag for AVPlayer. Tagging
	//     an H.264 stream "hvc1" makes players read it as HEVC and fail, so the tag
	//     is applied ONLY when the source is HEVC (see probeVideoCodec). This keeps
	//     the remux correct whether the camera records H.265 or H.264.
	//
	// Corrupt-source path (TRACK.md EXT-1): Frigate's HEVC clip export sometimes
	// emits frames smeared across hundreds of hours (non-monotonic DTS), which the
	// async resampler above turns into a multi-hour clip — and actually HANGS
	// ffmpeg (it tries to pad the giant gaps with silence). When the source
	// duration is absurd we can't trust its timestamps at all, so we REBUILD them
	// from frame/sample order instead: video re-timestamped at the camera's fps via
	// the `setts` bitstream filter (still `-c copy`, no re-encode), audio via
	// `asetpts` on consumed samples. Validated on-device against a 41h clip → ~56s.
	codec := probeVideoCodec(ctx, raw)
	corrupt := clipDurationSeconds(ctx, raw) > corruptClipDurationThreshold.Seconds()

	tmp := cachePath + ".tmp"
	args := []string{"-nostdin", "-y"}
	if !corrupt {
		args = append(args, "-fflags", "+genpts")
	}
	args = append(args, "-i", raw, "-map", "0:v:0", "-map", "0:a:0?", "-c:v", "copy")
	if corrupt {
		args = append(args,
			"-bsf:v", fmt.Sprintf("setts=pts=N/(%d*TB):dts=N/(%d*TB)", clipRebuildFPS, clipRebuildFPS),
			"-c:a", "aac", "-b:a", "128k", "-af", "asetpts=NB_CONSUMED_SAMPLES/SR/TB")
	} else {
		args = append(args, "-c:a", "aac", "-b:a", "128k", "-af", "aresample=async=1:first_pts=0")
	}
	args = append(args, "-movflags", "+faststart")
	if codec == "hevc" {
		args = append(args, "-tag:v", "hvc1")
	}
	args = append(args, "-f", "mp4", tmp) // temp file ends in .tmp, so force the muxer

	cmd := exec.CommandContext(ctx, "ffmpeg", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("ffmpeg remux clip: %w (%s)", err, lastLine(out))
	}
	return os.Rename(tmp, cachePath)
}

const (
	// corruptClipDurationThreshold: a real Frigate event clip is at most minutes;
	// anything past this is the EXT-1 timestamp corruption (frames smeared across
	// hundreds of hours), which triggers the rebuild-timestamps remux path. Set
	// generously so it can never false-positive on a legitimate event clip.
	corruptClipDurationThreshold = 2 * time.Hour
	// clipRebuildFPS is the frame rate used to rebuild timestamps for a corrupt
	// clip (the deimos main stream runs at 20fps). The corrupt source's own frame
	// rate is unreadable, so we assume the camera's configured rate.
	clipRebuildFPS = 20
)

// probeVideoCodec returns the first video stream's codec name (e.g. "hevc",
// "h264") via ffprobe, or "" if it can't be determined. Used to decide the
// output codec tag in the remux.
func probeVideoCodec(ctx context.Context, path string) string {
	out, err := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-select_streams", "v:0",
		"-show_entries", "stream=codec_name",
		"-of", "default=nw=1:nk=1",
		path,
	).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// clipDurationSeconds returns the container duration in seconds via ffprobe, or 0
// if it can't be determined. Used to detect the EXT-1 corruption (absurd duration).
func clipDurationSeconds(ctx context.Context, path string) float64 {
	out, err := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-show_entries", "format=duration",
		"-of", "default=nw=1:nk=1",
		path,
	).Output()
	if err != nil {
		return 0
	}
	d, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return 0
	}
	return d
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
