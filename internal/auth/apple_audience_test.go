package auth

import "testing"

func TestAppleVerifierAudienceAllowed(t *testing.T) {
	// Empty/duplicate audiences are dropped; the rest form the accepted set.
	v := NewAppleVerifier("org.tarazel.beacon", "org.tarazel.beacon.signin", "", "org.tarazel.beacon")

	if len(v.audiences) != 2 {
		t.Fatalf("expected 2 audiences after dedupe/empty-drop, got %d (%v)", len(v.audiences), v.audiences)
	}

	cases := []struct {
		name string
		aud  []string
		want bool
	}{
		{"ios bundle", []string{"org.tarazel.beacon"}, true},
		{"android services id", []string{"org.tarazel.beacon.signin"}, true},
		{"one of several", []string{"other.app", "org.tarazel.beacon"}, true},
		{"unknown", []string{"com.evil.app"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		if got := v.audienceAllowed(tc.aud); got != tc.want {
			t.Errorf("%s: audienceAllowed(%v) = %v, want %v", tc.name, tc.aud, got, tc.want)
		}
	}
}
