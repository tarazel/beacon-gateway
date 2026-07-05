package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	appleJWKSURL  = "https://appleid.apple.com/auth/keys"
	appleIssuer   = "https://appleid.apple.com"
	appleCacheTTL = 1 * time.Hour
)

type AppleIdentity struct {
	Sub           string
	Email         string
	EmailVerified bool
}

type AppleVerifier struct {
	// audiences is the set of accepted `aud` values. iOS presents the native app
	// bundle id; the Android web (Sign in with Apple) flow presents an Apple
	// Services ID — both must be accepted, so this is a set, not a single string.
	audiences []string
	http      *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	keysFetch time.Time
}

// NewAppleVerifier accepts one or more allowed audiences (empties/dupes dropped).
func NewAppleVerifier(clientIDs ...string) *AppleVerifier {
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
	return &AppleVerifier{
		audiences: auds,
		http:      &http.Client{Timeout: 10 * time.Second},
		keys:      map[string]*rsa.PublicKey{},
	}
}

// audienceAllowed reports whether any of the token's audiences is accepted.
func (v *AppleVerifier) audienceAllowed(aud []string) bool {
	for _, a := range aud {
		for _, allowed := range v.audiences {
			if a == allowed {
				return true
			}
		}
	}
	return false
}

func (v *AppleVerifier) Verify(ctx context.Context, identityToken string) (*AppleIdentity, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(identityToken, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.keyFor(ctx, kid)
	},
		jwt.WithIssuer(appleIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("verify apple token: %w", err)
	}

	// Audience is checked manually to accept a SET of allowed audiences (the iOS
	// bundle id and the Android Services ID) — jwt.WithAudience only accepts one.
	aud, _ := claims.GetAudience()
	if !v.audienceAllowed(aud) {
		return nil, errors.New("verify apple token: audience not allowed")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("missing sub claim")
	}
	id := &AppleIdentity{Sub: sub}
	if e, ok := claims["email"].(string); ok {
		id.Email = e
	}
	switch v := claims["email_verified"].(type) {
	case bool:
		id.EmailVerified = v
	case string:
		id.EmailVerified = v == "true"
	}
	return id, nil
}

func (v *AppleVerifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if key, ok := v.keys[kid]; ok && time.Since(v.keysFetch) < appleCacheTTL {
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
		return nil, fmt.Errorf("apple kid %q not found in JWKS", kid)
	}
	return key, nil
}

// rsaJWKS / rsaJWK model an RSA JWK set. Both Apple's and Google's key endpoints
// serve this shape, so the Google verifier reuses these types and jwkToRSA.
type rsaJWKS struct {
	Keys []rsaJWK `json:"keys"`
}

type rsaJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *AppleVerifier) refreshKeys(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, appleJWKSURL, nil)
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch apple jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch apple jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var jwks rsaJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parse apple jwks: %w", err)
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

func jwkToRSA(k rsaJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}
