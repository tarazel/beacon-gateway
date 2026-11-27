package frigate

import "testing"

func TestParseEventRejectsUnsafeIDs(t *testing.T) {
	for id, ok := range map[string]bool{
		"1732730000.123456-ab12cd": true,
		"evt_1":                    true,
		"":                         false,
		"..":                       false,
		".hidden":                  false,
		"../../etc/x":              false,
		"a/b":                      false,
		`a\\b`:                     false,
		"a?b":                      false,
	} {
		_, err := ParseEvent([]byte(`{"type":"new","after":{"id":"` + id + `"}}`))
		if (err == nil) != ok {
			t.Errorf("id %q: err=%v, want ok=%v", id, err, ok)
		}
	}
}
