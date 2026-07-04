package api

import (
	"net/url"
	"strings"
	"testing"
)

func TestRewriteHLSPlaylist(t *testing.T) {
	playlistURL, _ := url.Parse("http://go2rtc:1984/api/stream.m3u8?src=front_sub")
	// makeProxy records the absolute URLs it's handed and returns a stable marker
	// so the output is easy to assert on.
	var seen []string
	makeProxy := func(abs string) string {
		seen = append(seen, abs)
		return "PROXY(" + abs + ")"
	}

	in := strings.Join([]string{
		"#EXTM3U",
		"#EXT-X-VERSION:6",
		`#EXT-X-MAP:URI="init.mp4"`,
		`#EXT-X-KEY:METHOD=AES-128,URI="https://go2rtc:1984/api/key?id=1",IV=0x0`,
		"#EXTINF:2.000,",
		"segment0.mp4?id=abc",
		"#EXTINF:2.000,",
		"/api/hls/segment1.mp4?id=def",
		"", // trailing blank
	}, "\n")

	out := string(rewriteHLSPlaylist([]byte(in), playlistURL, makeProxy))

	// Tag lines without a URI pass through untouched.
	if !strings.Contains(out, "#EXTM3U") || !strings.Contains(out, "#EXT-X-VERSION:6") ||
		!strings.Contains(out, "#EXTINF:2.000,") {
		t.Errorf("passthrough tags altered:\n%s", out)
	}

	// Relative and absolute refs are resolved against the playlist URL, then proxied.
	wantResolved := map[string]bool{
		"http://go2rtc:1984/api/init.mp4":                true, // EXT-X-MAP relative
		"https://go2rtc:1984/api/key?id=1":               true, // EXT-X-KEY absolute
		"http://go2rtc:1984/api/segment0.mp4?id=abc":     true, // bare relative segment
		"http://go2rtc:1984/api/hls/segment1.mp4?id=def": true, // root-relative segment
	}
	for _, s := range seen {
		delete(wantResolved, s)
	}
	if len(wantResolved) != 0 {
		t.Errorf("these URIs were not resolved+proxied as expected: %v\nseen: %v", wantResolved, seen)
	}

	// The EXT-X-MAP URI attribute is rewritten in place (quotes preserved).
	if !strings.Contains(out, `#EXT-X-MAP:URI="PROXY(http://go2rtc:1984/api/init.mp4)"`) {
		t.Errorf("EXT-X-MAP URI not rewritten in place:\n%s", out)
	}
	// A bare segment line is fully replaced by the proxy URL.
	if !strings.Contains(out, "PROXY(http://go2rtc:1984/api/segment0.mp4?id=abc)") {
		t.Errorf("bare segment not rewritten:\n%s", out)
	}
}

func TestIsHLSPlaylist(t *testing.T) {
	cases := []struct {
		ct, path string
		want     bool
	}{
		{"application/vnd.apple.mpegurl", "/api/stream.m3u8", true},
		{"application/x-mpegURL", "/x", true},
		{"video/mp2t", "/api/segment0.ts", false},
		{"", "/api/media.m3u8", true},
		{"video/mp4", "/api/init.mp4", false},
	}
	for _, c := range cases {
		if got := isHLSPlaylist(c.ct, c.path); got != c.want {
			t.Errorf("isHLSPlaylist(%q,%q)=%v want %v", c.ct, c.path, got, c.want)
		}
	}
}
