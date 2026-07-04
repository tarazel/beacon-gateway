package notifrules

import (
	"testing"
	"time"
)

func at(hour, min int) time.Time {
	return time.Date(2026, 7, 4, hour, min, 0, 0, time.UTC)
}

func TestStaticAllows_Filters(t *testing.T) {
	noon := at(12, 0)
	tests := []struct {
		name string
		rule Rule
		ev   Event
		want bool
	}{
		{"default allows all", DefaultRule(), Event{Label: "car", Score: 0.1}, true},
		{"label in allowlist", Rule{Labels: []string{"person", "dog"}, QuietStartMin: -1, QuietEndMin: -1}, Event{Label: "person"}, true},
		{"label not in allowlist", Rule{Labels: []string{"person"}, QuietStartMin: -1, QuietEndMin: -1}, Event{Label: "car"}, false},
		{"zone overlap", Rule{Zones: []string{"driveway"}, QuietStartMin: -1, QuietEndMin: -1}, Event{Zones: []string{"yard", "driveway"}}, true},
		{"zone no overlap", Rule{Zones: []string{"driveway"}, QuietStartMin: -1, QuietEndMin: -1}, Event{Zones: []string{"yard"}}, false},
		{"score below min", Rule{MinScore: 0.7, QuietStartMin: -1, QuietEndMin: -1}, Event{Score: 0.5}, false},
		{"score meets min", Rule{MinScore: 0.7, QuietStartMin: -1, QuietEndMin: -1}, Event{Score: 0.7}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.staticAllows(tc.ev, noon); got != tc.want {
				t.Errorf("staticAllows = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQuietHours(t *testing.T) {
	// Overnight window 22:00 (1320) .. 07:00 (420) — wraps midnight.
	overnight := Rule{QuietStartMin: 1320, QuietEndMin: 420}
	// Daytime window 09:00 (540) .. 17:00 (1020) — no wrap.
	daytime := Rule{QuietStartMin: 540, QuietEndMin: 1020}

	cases := []struct {
		name string
		rule Rule
		now  time.Time
		want bool // want quiet (suppressed)
	}{
		{"overnight, 23:00 is quiet", overnight, at(23, 0), true},
		{"overnight, 03:00 is quiet", overnight, at(3, 0), true},
		{"overnight, 07:00 exactly is NOT quiet (end exclusive)", overnight, at(7, 0), false},
		{"overnight, noon is not quiet", overnight, at(12, 0), false},
		{"daytime, 12:00 is quiet", daytime, at(12, 0), true},
		{"daytime, 08:00 is not quiet", daytime, at(8, 0), false},
		{"disabled window", DefaultRule(), at(3, 0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.inQuietHours(tc.now); got != tc.want {
				t.Errorf("inQuietHours = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalized_ClampsAndDedupes(t *testing.T) {
	r := Rule{
		Labels:          []string{"person", " person ", "", "car"},
		MinScore:        1.5,
		CooldownSeconds: -10,
		QuietStartMin:   1320,
		QuietEndMin:     -1, // one bound disabled -> both disabled
	}.normalized()

	if len(r.Labels) != 2 || r.Labels[0] != "person" || r.Labels[1] != "car" {
		t.Errorf("labels not trimmed/deduped: %v", r.Labels)
	}
	if r.MinScore != 1 {
		t.Errorf("min_score not clamped to 1: %v", r.MinScore)
	}
	if r.CooldownSeconds != 0 {
		t.Errorf("negative cooldown not clamped: %v", r.CooldownSeconds)
	}
	if r.QuietStartMin != -1 || r.QuietEndMin != -1 {
		t.Errorf("half-disabled quiet hours should disable both: %d..%d", r.QuietStartMin, r.QuietEndMin)
	}
}
