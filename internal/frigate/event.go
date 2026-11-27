package frigate

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// eventID matches Frigate's ids ("<unix time>-<random>"). Ids become file names
// and URL path segments, and anything able to publish to the broker chooses them,
// so separators and leading dots are refused.
var eventID = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)

type EventPhase string

const (
	PhaseNew    EventPhase = "new"
	PhaseUpdate EventPhase = "update"
	PhaseEnd    EventPhase = "end"
)

type MQTTEvent struct {
	Type   EventPhase  `json:"type"`
	Before *EventState `json:"before"`
	After  EventState  `json:"after"`
}

type EventState struct {
	ID          string   `json:"id"`
	Camera      string   `json:"camera"`
	Label       string   `json:"label"`
	SubLabel    *string  `json:"sub_label"`
	StartTime   float64  `json:"start_time"`
	EndTime     *float64 `json:"end_time"`
	TopScore    float64  `json:"top_score"`
	HasSnapshot bool     `json:"has_snapshot"`
	HasClip     bool     `json:"has_clip"`
	Zones       []string `json:"current_zones"`
}

func ParseEvent(payload []byte) (*MQTTEvent, error) {
	var e MQTTEvent
	if err := json.Unmarshal(payload, &e); err != nil {
		return nil, err
	}
	if !eventID.MatchString(e.After.ID) {
		return nil, fmt.Errorf("invalid event id %q", e.After.ID)
	}
	return &e, nil
}
