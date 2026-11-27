package auth

import (
	"errors"
	"strings"
	"testing"
)

// The apps and the relay compute the same value; changing it breaks sign-in.
func TestBoundNonceVector(t *testing.T) {
	got := BoundNonce("https://gw.example.com", strings.Repeat("s", 43))
	const want = "7cbc1910942b475e4072b094a1e4bc0fe5e535cce9e23bf73a45b9e0622d567b"
	if got != want {
		t.Fatalf("BoundNonce = %s", got)
	}
}

func TestCanonicalOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://GW.Example.com":         "https://gw.example.com",
		"https://gw.example.com:443/":    "https://gw.example.com",
		"http://192.168.1.5:8080/path?q": "http://192.168.1.5:8080",
		"http://gw.example.com:80":       "http://gw.example.com",
		" https://gw.example.com:8443 ":  "https://gw.example.com:8443",
		"http://[fd00::1]:8080/":         "http://[fd00::1]:8080",
	} {
		got, err := CanonicalOrigin(in)
		if err != nil || got != want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "gw.example.com", "ftp://gw.example.com", "https://"} {
		if _, err := CanonicalOrigin(bad); err == nil {
			t.Errorf("CanonicalOrigin(%q) should fail", bad)
		}
	}
}

func TestNoncePolicy(t *testing.T) {
	secret := strings.Repeat("k", 43)
	mine := "https://mine.example.com"
	p := NoncePolicy{Origins: []string{mine}, Required: true}

	if origin, err := p.Check(BoundNonce(mine, secret), secret); err != nil || origin != mine {
		t.Fatalf("valid binding rejected: %q %v", origin, err)
	}
	for name, tc := range map[string]struct{ claim, secret string }{
		"token bound to another gateway": {BoundNonce("https://evil.example.com", secret), secret},
		"wrong secret":                   {BoundNonce(mine, secret), strings.Repeat("z", 43)},
		"no secret":                      {BoundNonce(mine, secret), ""},
		"no claim":                       {"", secret},
		"short secret":                   {BoundNonce(mine, "short"), "short"},
	} {
		if _, err := p.Check(tc.claim, tc.secret); !errors.Is(err, ErrNonce) {
			t.Errorf("%s: want ErrNonce, got %v", name, err)
		}
	}

	lax := NoncePolicy{Origins: []string{mine}}
	if _, err := lax.Check("anything", ""); err != nil {
		t.Errorf("optional policy should accept a missing secret: %v", err)
	}
	if _, err := lax.Check("wrong", secret); err == nil {
		t.Error("optional policy must still reject a mismatched secret")
	}
}
