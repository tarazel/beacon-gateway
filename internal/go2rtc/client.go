package go2rtc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	base    *url.URL // parsed baseURL, for validating URLs the HLS proxy fetches
	http    *http.Client
	// stream has no total timeout so HLS segments/playlists can be proxied under
	// the caller's request context; ResponseHeaderTimeout still bounds a dead upstream.
	stream *http.Client
}

func NewClient(baseURL string) *Client {
	trimmed := strings.TrimRight(baseURL, "/")
	base, _ := url.Parse(trimmed)
	return &Client{
		baseURL: trimmed,
		base:    base,
		http:    &http.Client{Timeout: 15 * time.Second},
		stream: &http.Client{
			Transport: &http.Transport{ResponseHeaderTimeout: 15 * time.Second},
			// A redirect would leave the validated URL behind.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// HLSPlaylistURL is go2rtc's HLS playlist URL for a stream. The substream this
// maps to is H.264 (the hard project rule), so go2rtc serves an AVPlayer-playable
// playlist without transcoding.
func (c *Client) HLSPlaylistURL(stream string) string {
	return fmt.Sprintf("%s/api/stream.m3u8?src=%s", c.baseURL, url.QueryEscape(stream))
}

// IsHLSResource reports whether u is a playlist or segment on this go2rtc
// instance: same scheme+host, under /api/hls/. The HLS proxy MUST gate every
// client-supplied URL through this. A host check alone is not enough, because the
// rest of go2rtc's API (/api/config, /api/streams, …) returns camera credentials
// and every camera's media.
func (c *Client) IsHLSResource(u *url.URL) bool {
	if c.base == nil || u == nil || u.User != nil || u.Scheme != c.base.Scheme || u.Host != c.base.Host {
		return false
	}
	// u.Path is already percent-decoded; requiring it to be clean rejects "..".
	return path.Clean(u.Path) == u.Path && strings.HasPrefix(u.Path, c.base.Path+"/api/hls/")
}

// GetHLS GETs a go2rtc HLS resource (playlist or segment) for proxying, streaming
// under ctx. Callers must validate client-supplied URLs with IsHLSResource first.
func (c *Client) GetHLS(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.stream.Do(req)
}

// WHEP performs a WebRTC SDP exchange against go2rtc for the named stream.
// The request body is the client's SDP offer; the response is go2rtc's SDP answer.
func (c *Client) WHEP(ctx context.Context, stream string, offerSDP []byte) ([]byte, error) {
	u := fmt.Sprintf("%s/api/webrtc?src=%s", c.baseURL, url.QueryEscape(stream))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(offerSDP))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/sdp")
	req.Header.Set("Accept", "application/sdp")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go2rtc request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("go2rtc whep status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
