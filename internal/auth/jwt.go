package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuer = "beacon-gateway"

// ScopeMedia marks a long-lived token usable ONLY on media endpoints
// (snapshots/clips). The notification service extension uses it because it can't
// refresh the short-lived access token. A normal full-access token has no scope
// (empty), so it is omitted from the JSON.
const ScopeMedia = "media"

// ScopeHLS marks a short-lived token usable ONLY on the HLS live-view endpoints.
// It's issued by the live descriptor and embedded in the returned HLS URL as a
// query param, so AVPlayer (which can't set Authorization headers on HLS segment
// requests) can play the stream directly. It carries the user's sub, so per-camera
// access is still enforced; a short TTL bounds the URL-leak blast radius.
const ScopeHLS = "hls"

type Claims struct {
	UserID string `json:"sub"`
	Scope  string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

type JWTIssuer struct {
	key []byte
	ttl time.Duration
}

func NewJWTIssuer(key []byte, ttl time.Duration) *JWTIssuer {
	return &JWTIssuer{key: key, ttl: ttl}
}

// Issue mints a normal full-access token with the configured (short) TTL.
func (i *JWTIssuer) Issue(userID string) (string, time.Time, error) {
	return i.issue(userID, "", i.ttl)
}

// IssueMedia mints a long-lived, media-scoped token for the notification service
// extension (which can't refresh). It still carries the user's sub, so per-camera
// access is enforced normally; a leak only exposes that user's media.
func (i *JWTIssuer) IssueMedia(userID string, ttl time.Duration) (string, time.Time, error) {
	return i.issue(userID, ScopeMedia, ttl)
}

// IssueHLS mints a short-lived, HLS-scoped token for one live-view session,
// embedded in the HLS URL so AVPlayer can play it directly (see ScopeHLS).
func (i *JWTIssuer) IssueHLS(userID string, ttl time.Duration) (string, time.Time, error) {
	return i.issue(userID, ScopeHLS, ttl)
}

func (i *JWTIssuer) issue(userID, scope string, ttl time.Duration) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(ttl)
	claims := Claims{
		UserID: userID,
		Scope:  scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	return signed, exp, nil
}

func (i *JWTIssuer) Parse(raw string) (*Claims, error) {
	c := &Claims{}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %s", t.Method.Alg())
		}
		return i.key, nil
	}, jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	if c.UserID == "" {
		return nil, errors.New("missing sub claim")
	}
	return c, nil
}
