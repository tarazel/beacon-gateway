package api

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hydak/beacon-gateway/internal/auth"
)

// HLS off-network live view.
//
// WebRTC live view needs UDP, which the HTTP-only Cloudflare tunnel doesn't
// carry, so it only works on-LAN. HLS rides plain HTTP through the tunnel, so it
// works anywhere. go2rtc produces the HLS from the H.264 substream (the hard
// project rule — no HEVC on a user-facing path).
//
// The gateway is the only public surface, so it PROXIES the playlist and every
// segment from go2rtc rather than exposing go2rtc. The playlist's media URIs are
// rewritten to point back at HLSResource, each carrying the original absolute
// go2rtc URL (base64) plus the caller's token. HLSResource SameOrigin-validates
// that URL before fetching (the URL comes from a client param — without the check
// it would be an SSRF hole).

const maxPlaylistBytes = 1 << 20 // 1 MiB — playlists are tiny; segments stream unbounded

// HLSIndex serves the (rewritten) top-level HLS playlist for a camera.
func (h *Handlers) HLSIndex(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	cam, ok := h.cameras.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "camera not found")
		return
	}
	if !h.ensureCameraAccess(w, r, userID, id) {
		return
	}

	playlistURLStr := h.go2rtc.HLSPlaylistURL(cam.Stream)
	resp, err := h.go2rtc.GetHLS(r.Context(), playlistURLStr)
	if err != nil {
		h.log.Warn("hls playlist fetch failed", "camera", id, "err", err)
		writeError(w, http.StatusBadGateway, "stream unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "stream unavailable")
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPlaylistBytes))
	if err != nil {
		writeError(w, http.StatusBadGateway, "stream unavailable")
		return
	}

	playlistURL, _ := url.Parse(playlistURLStr)
	token := hlsToken(r)
	rewritten := rewriteHLSPlaylist(body, playlistURL, func(abs string) string {
		return h.hlsResourceURL(id, token, abs)
	})
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(rewritten)
}

// HLSResource proxies a single go2rtc HLS resource (a nested playlist or a media
// segment), identified by the base64 `u` param produced by rewriteHLSPlaylist.
func (h *Handlers) HLSResource(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if _, ok := h.cameras.Get(id); !ok {
		writeError(w, http.StatusNotFound, "camera not found")
		return
	}
	if !h.ensureCameraAccess(w, r, userID, id) {
		return
	}

	rawURL, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("u"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource")
		return
	}
	target, err := url.Parse(string(rawURL))
	if err != nil || !h.go2rtc.SameOrigin(target) {
		// SameOrigin guards against a client pointing `u` at an arbitrary host.
		writeError(w, http.StatusBadRequest, "invalid resource")
		return
	}

	resp, err := h.go2rtc.GetHLS(r.Context(), target.String())
	if err != nil {
		h.log.Warn("hls resource fetch failed", "camera", id, "err", err)
		writeError(w, http.StatusBadGateway, "stream unavailable")
		return
	}
	defer resp.Body.Close()

	// A nested/media playlist is rewritten too; anything else (segments, init,
	// keys) is streamed through verbatim.
	if isHLSPlaylist(resp.Header.Get("Content-Type"), target.Path) {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPlaylistBytes))
		if err != nil {
			writeError(w, http.StatusBadGateway, "stream unavailable")
			return
		}
		token := hlsToken(r)
		rewritten := rewriteHLSPlaylist(body, target, func(abs string) string {
			return h.hlsResourceURL(id, token, abs)
		})
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(rewritten)
		return
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hlsResourceURL builds the gateway URL a rewritten playlist entry points at:
// the absolute go2rtc URL (base64) plus the caller's token, so AVPlayer can fetch
// segments directly (no Authorization header needed).
func (h *Handlers) hlsResourceURL(cameraID, token, absURL string) string {
	base := strings.TrimRight(h.cfg.PublicBaseURL, "/")
	q := url.Values{"u": {base64.RawURLEncoding.EncodeToString([]byte(absURL))}, "token": {token}}
	return base + "/api/cameras/" + cameraID + "/hls/r?" + q.Encode()
}

// hlsToken returns the caller's token from the query param (AVPlayer path) or the
// Bearer header. HLSMiddleware already validated it; this just echoes it into the
// rewritten child URLs so segment requests carry it too.
func hlsToken(r *http.Request) string {
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func isHLSPlaylist(contentType, path string) bool {
	if strings.Contains(strings.ToLower(contentType), "mpegurl") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(path), ".m3u8")
}

// rewriteHLSPlaylist rewrites every media/segment URI in an m3u8 so it routes
// back through the gateway. Bare URI lines (segments, variant playlists) and the
// URI="..." attribute of tags (EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA, EXT-X-PART,
// EXT-X-PRELOAD-HINT, …) are resolved against the playlist URL to an absolute
// go2rtc URL, then handed to makeProxy. Comment/tag lines without a URI, and blank
// lines, pass through unchanged.
func rewriteHLSPlaylist(body []byte, playlistURL *url.URL, makeProxy func(absURL string) string) []byte {
	resolve := func(ref string) string {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return ref
		}
		if playlistURL == nil {
			return makeProxy(ref)
		}
		u, err := playlistURL.Parse(ref)
		if err != nil {
			return makeProxy(ref)
		}
		return makeProxy(u.String())
	}

	lines := strings.Split(string(body), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			if uri, lo, hi, ok := findURIAttr(line); ok {
				lines[i] = line[:lo] + resolve(uri) + line[hi:]
			}
			continue
		}
		lines[i] = resolve(trimmed)
	}
	return []byte(strings.Join(lines, "\n"))
}

// findURIAttr locates a URI="..." attribute in an m3u8 tag line, returning the
// inner value and the byte range [lo,hi) of that value (exclusive of the quotes).
func findURIAttr(line string) (uri string, lo, hi int, ok bool) {
	const marker = `URI="`
	idx := strings.Index(line, marker)
	if idx < 0 {
		return "", 0, 0, false
	}
	lo = idx + len(marker)
	rel := strings.IndexByte(line[lo:], '"')
	if rel < 0 {
		return "", 0, 0, false
	}
	hi = lo + rel
	return line[lo:hi], lo, hi, true
}
