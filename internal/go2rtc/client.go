package go2rtc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 15 * time.Second},
	}
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
