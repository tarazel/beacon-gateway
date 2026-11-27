package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// A provider ID token on its own says who signed in, not which server it was
// meant for: every gateway sees tokens with the same audience, so one gateway
// could replay a token to another. To bind them, the app generates a random
// secret, asks the provider to embed BoundNonce(origin, secret) as the token's
// nonce, and sends the secret to the gateway it is signing in to. The gateway
// recomputes the nonce with its own origin. A token captured elsewhere — by
// another gateway, or by an app intercepting a browser redirect — doesn't match.
//
// The iOS and Android apps and the push relay implement the same formula.

const nonceDomain = "beacon-signin-v1"

// minNonceSecret is the shortest secret accepted (the apps send 32 random bytes,
// 43 characters in base64url).
const minNonceSecret = 32

// BoundNonce is the nonce an app requests from the provider when signing in to
// the gateway at origin.
func BoundNonce(origin, secret string) string {
	sum := sha256.Sum256([]byte(nonceDomain + "\n" + origin + "\n" + secret))
	return hex.EncodeToString(sum[:])
}

// CanonicalOrigin reduces a URL to the "scheme://host[:port]" form both sides
// hash: lower-cased, without a default port, path, or trailing slash.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	if (scheme != "http" && scheme != "https") || host == "" {
		return "", fmt.Errorf("%q is not an http(s) URL", raw)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// ErrNonce means a sign-in token isn't bound to this gateway.
var ErrNonce = errors.New("sign-in token is not bound to this gateway")

// NoncePolicy checks that sign-in tokens were requested for this gateway.
type NoncePolicy struct {
	// Origins are the canonical origins apps use to reach this gateway.
	Origins []string
	// Required rejects sign-ins that carry no nonce secret. Turning it off only
	// makes sense while old app builds are still in use.
	Required bool
}

// Check verifies a token's nonce claim against the secret the app supplied, and
// returns the gateway origin it is bound to ("" when no secret was supplied and
// none is required).
func (p NoncePolicy) Check(claim, secret string) (string, error) {
	if secret == "" {
		if p.Required {
			return "", fmt.Errorf("%w: no nonce secret (is the app up to date?)", ErrNonce)
		}
		return "", nil
	}
	if len(secret) < minNonceSecret {
		return "", fmt.Errorf("%w: nonce secret too short", ErrNonce)
	}
	for _, origin := range p.Origins {
		if subtle.ConstantTimeCompare([]byte(claim), []byte(BoundNonce(origin, secret))) == 1 {
			return origin, nil
		}
	}
	return "", fmt.Errorf("%w: nonce does not match %v (check PUBLIC_BASE_URL)", ErrNonce, p.Origins)
}
