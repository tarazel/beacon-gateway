package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
	googleCacheTTL = 1 * time.Hour
)

// googleIssuers are the two `iss` values Google mints ID tokens with. Either is
// valid; jwt.WithIssuer only accepts one, so issuer is checked manually.
var googleIssuers = map[string]bool{
	"https://accounts.google.com": true,
	"accounts.google.com":         true,
}

type GoogleIdentity struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

// GoogleVerifier validates Google Sign-In ID tokens (RS256, JWKS-signed). Like
// AppleVerifier it accepts a SET of audiences: the token's `aud` is the OAuth
// client id that requested it — the Android Credential Manager server client id,
// the iOS client id, and any web client id can each appear, so all configured
// audiences are accepted.
type GoogleVerifier struct {
	audiences []string
	http      *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	keysFetch time.Time
}

// NewGoogleVerifier accepts one or more allowed audiences (empties/dupes dropped).
// If none are supplied the verifier is considered unconfigured (Configured()==false)
// and Verify always fails — the gateway then rejects /api/auth/google with a clear
// "not configured" error rather than accepting unaudienced tokens.
func NewGoogleVerifier(clientIDs ...string) *GoogleVerifier {
	seen := map[string]bool{}
	auds := make([]string, 0, len(clientIDs))
	for _, c := range clientIDs {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		auds = append(auds, c)
	}
	return &GoogleVerifier{
		audiences: auds,
		http:      &http.Client{Timeout: 10 * time.Second},
		keys:      map[string]*rsa.PublicKey{},
	}
}

// Configured reports whether any audience was supplied. When false, Google sign-in
// is disabled for the instance.
func (v *GoogleVerifier) Configured() bool { return len(v.audiences) > 0 }

func (v *GoogleVerifier) audienceAllowed(aud []string) bool {
	for _, a := range aud {
		for _, allowed := range v.audiences {
			if a == allowed {
				return true
			}
		}
	}
	return false
}

func (v *GoogleVerifier) Verify(ctx context.Context, idToken string) (*GoogleIdentity, error) {
	if !v.Configured() {
		return nil, errors.New("google sign-in not configured")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.keyFor(ctx, kid)
	},
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("verify google token: %w", err)
	}

	// Issuer is one of two accepted values; audience is a set (see type doc).
	iss, _ := claims.GetIssuer()
	if !googleIssuers[iss] {
		return nil, fmt.Errorf("verify google token: unexpected issuer %q", iss)
	}
	aud, _ := claims.GetAudience()
	if !v.audienceAllowed(aud) {
		return nil, errors.New("verify google token: audience not allowed")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("missing sub claim")
	}
	id := &GoogleIdentity{Sub: sub}
	if e, ok := claims["email"].(string); ok {
		id.Email = e
	}
	switch ev := claims["email_verified"].(type) {
	case bool:
		id.EmailVerified = ev
	case string:
		id.EmailVerified = ev == "true"
	}
	if n, ok := claims["name"].(string); ok {
		id.Name = n
	}
	return id, nil
}

func (v *GoogleVerifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if key, ok := v.keys[kid]; ok && time.Since(v.keysFetch) < googleCacheTTL {
		v.mu.Unlock()
		return key, nil
	}
	v.mu.Unlock()

	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("google kid %q not found in JWKS", kid)
	}
	return key, nil
}

func (v *GoogleVerifier) refreshKeys(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, googleJWKSURL, nil)
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch google jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch google jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var jwks rsaJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parse google jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	v.mu.Lock()
	v.keys = keys
	v.keysFetch = time.Now()
	v.mu.Unlock()
	return nil
}
