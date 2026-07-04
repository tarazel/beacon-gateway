// Package notifrules holds each user's server-side notification rules and the
// logic that decides, per family member, whether a given event should notify
// them. It is applied in the push dispatcher AFTER camera scope + mute and
// BEFORE delivery, so different members can tune the same event stream (one
// drops "car", another goes quiet after 21:00) and pushes they don't want never
// reach the relay.
package notifrules

import "time"

// Rule is a user's notification preferences. Its zero value is "notify for
// everything", so a user with no stored row (DefaultRule) is never filtered.
type Rule struct {
	Labels          []string `json:"labels"`           // empty = all labels
	Zones           []string `json:"zones"`            // empty = all zones
	MinScore        float64  `json:"min_score"`        // 0 = any
	CooldownSeconds int      `json:"cooldown_seconds"` // 0 = no cooldown
	QuietStartMin   int      `json:"quiet_start_min"`  // minutes from local midnight; -1 = disabled
	QuietEndMin     int      `json:"quiet_end_min"`    // minutes from local midnight; -1 = disabled
}

// DefaultRule is the allow-everything rule used when a user has no stored row.
func DefaultRule() Rule {
	return Rule{QuietStartMin: -1, QuietEndMin: -1}
}

// Event is the subset of an event a Rule evaluates against.
type Event struct {
	Camera string
	Label  string
	Zones  []string
	Score  float64
}

// staticAllows applies the stateless filters (label, zone, min score, quiet
// hours) at local time `now`. Cooldown is stateful and lives in Store.
func (r Rule) staticAllows(ev Event, now time.Time) bool {
	if len(r.Labels) > 0 && !contains(r.Labels, ev.Label) {
		return false
	}
	if len(r.Zones) > 0 && !anyOverlap(r.Zones, ev.Zones) {
		return false
	}
	if r.MinScore > 0 && ev.Score < r.MinScore {
		return false
	}
	if r.inQuietHours(now) {
		return false
	}
	return true
}

// inQuietHours reports whether now falls inside the user's quiet window. The
// window may wrap past midnight (start > end, e.g. 22:00..07:00). Disabled when
// either bound is negative or the two bounds are equal (an empty window).
func (r Rule) inQuietHours(now time.Time) bool {
	if r.QuietStartMin < 0 || r.QuietEndMin < 0 || r.QuietStartMin == r.QuietEndMin {
		return false
	}
	m := now.Hour()*60 + now.Minute()
	if r.QuietStartMin < r.QuietEndMin {
		return m >= r.QuietStartMin && m < r.QuietEndMin
	}
	return m >= r.QuietStartMin || m < r.QuietEndMin // wraps midnight
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// anyOverlap reports whether the two sets share at least one element.
func anyOverlap(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}
