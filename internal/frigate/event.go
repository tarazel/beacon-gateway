package frigate

import "encoding/json"

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
	return &e, nil
}
