package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAppleCallbackRedirectsTokenToApp(t *testing.T) {
	h := &Handlers{}
	form := url.Values{"id_token": {"tok123"}, "state": {"st456"}, "code": {"c"}}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/apple/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.AppleCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Scheme != "beacon-auth" || u.Host != "callback" {
		t.Fatalf("redirect = %s://%s, want beacon-auth://callback", u.Scheme, u.Host)
	}
	q := u.Query()
	if q.Get("id_token") != "tok123" || q.Get("state") != "st456" {
		t.Fatalf("redirect query = %v, want id_token=tok123 & state=st456", q)
	}
}

func TestAppleCallbackForwardsError(t *testing.T) {
	h := &Handlers{}
	form := url.Values{"error": {"user_cancelled_authorize"}}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/apple/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.AppleCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if got := u.Query().Get("error"); got != "user_cancelled_authorize" {
		t.Fatalf("error param = %q, want user_cancelled_authorize", got)
	}
	if u.Query().Get("id_token") != "" {
		t.Fatalf("id_token must be absent on error, got %q", u.Query().Get("id_token"))
	}
}
