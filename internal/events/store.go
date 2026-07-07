package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/tarazel/beacon-gateway/internal/frigate"
)

type Event struct {
	ID          string     `json:"id"`
	Camera      string     `json:"camera"`
	Label       string     `json:"label"`
	SubLabel    *string    `json:"sub_label,omitempty"`
	StartTime   time.Time  `json:"start_time"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	TopScore    float64    `json:"top_score"`
	HasSnapshot bool       `json:"has_snapshot"`
	HasClip     bool       `json:"has_clip"`
	KeepClip    bool       `json:"keep_clip"`
	Zones       []string   `json:"zones,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// PushTitle returns the notification title for an event's camera. Kept here (not
// in cmd/gateway) so the MQTT dispatcher and the media-scoped push-metadata
// endpoint — which the NSE reads when it gets a privacy-minimal relay push —
// format notifications identically.
func PushTitle(camera string) string {
	if camera == "" {
		return "Activity detected"
	}
	return camera
}

// PushBody returns the notification body from an event's label / sub-label,
// preferring the sub-label (e.g. a recognized name) when present.
func PushBody(label string, sub *string) string {
	if sub != nil && *sub != "" {
		return *sub + " detected"
	}
	if label == "" {
		return "Motion detected"
	}
	return label + " detected"
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Upsert(ctx context.Context, ev *frigate.MQTTEvent, raw []byte) (created bool, err error) {
	state := ev.After
	zonesJSON, _ := json.Marshal(state.Zones)

	startTime := fromUnixFloat(state.StartTime)
	var endTime *int64
	if state.EndTime != nil {
		t := fromUnixFloat(*state.EndTime).Unix()
		endTime = &t
	}

	now := time.Now().Unix()

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO events (id, camera, label, sub_label, start_time, end_time, top_score, has_snapshot, has_clip, zones, raw_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			end_time = excluded.end_time,
			top_score = excluded.top_score,
			has_snapshot = excluded.has_snapshot,
			has_clip = excluded.has_clip,
			zones = excluded.zones,
			raw_json = excluded.raw_json,
			updated_at = excluded.updated_at
	`,
		state.ID,
		state.Camera,
		state.Label,
		nullStr(state.SubLabel),
		startTime.Unix(),
		endTime,
		state.TopScore,
		boolToInt(state.HasSnapshot),
		boolToInt(state.HasClip),
		string(zonesJSON),
		string(raw),
		now,
		now,
	)
	if err != nil {
		return false, err
	}
	rows, _ := res.RowsAffected()
	return ev.Type == frigate.PhaseNew && rows == 1, nil
}

// eventColumns is the shared SELECT list for the events table, kept in one place
// so List, Get, and GetByIDs stay in lockstep with scanEvent's column order.
const eventColumns = `id, camera, label, sub_label, start_time, end_time, top_score, has_snapshot, has_clip, keep_clip, zones, created_at, updated_at`

// scanRow is satisfied by both *sql.Row and *sql.Rows, so scanEvent works for
// single-row and multi-row queries.
type scanRow interface {
	Scan(dest ...any) error
}

// scanEvent reads one events row (columns in eventColumns order) into an Event.
func scanEvent(sc scanRow) (Event, error) {
	var e Event
	var subLabel sql.NullString
	var endTime sql.NullInt64
	var startUnix, createdUnix, updatedUnix int64
	var hasSnap, hasClip, keepClip int
	var zonesJSON string
	if err := sc.Scan(&e.ID, &e.Camera, &e.Label, &subLabel, &startUnix, &endTime, &e.TopScore, &hasSnap, &hasClip, &keepClip, &zonesJSON, &createdUnix, &updatedUnix); err != nil {
		return e, err
	}
	if subLabel.Valid {
		v := subLabel.String
		e.SubLabel = &v
	}
	e.StartTime = time.Unix(startUnix, 0)
	if endTime.Valid {
		t := time.Unix(endTime.Int64, 0)
		e.EndTime = &t
	}
	e.HasSnapshot = hasSnap == 1
	e.HasClip = hasClip == 1
	e.KeepClip = keepClip == 1
	_ = json.Unmarshal([]byte(zonesJSON), &e.Zones)
	e.CreatedAt = time.Unix(createdUnix, 0)
	e.UpdatedAt = time.Unix(updatedUnix, 0)
	return e, nil
}

type ListFilter struct {
	Camera string
	Label  string
	Since  *time.Time
	Until  *time.Time
	Limit  int
	// Cameras restricts results to this set of camera ids when non-empty. Used to
	// enforce a user's per-camera access scope; independent of the Camera filter.
	Cameras []string
}

func (s *Store) List(ctx context.Context, f ListFilter) ([]Event, error) {
	q := `SELECT ` + eventColumns + ` FROM events WHERE 1=1`
	args := []any{}
	if f.Camera != "" {
		q += " AND camera = ?"
		args = append(args, f.Camera)
	}
	if f.Label != "" {
		q += " AND label = ?"
		args = append(args, f.Label)
	}
	if len(f.Cameras) > 0 {
		q += " AND camera IN (" + placeholders(len(f.Cameras)) + ")"
		for _, c := range f.Cameras {
			args = append(args, c)
		}
	}
	if f.Since != nil {
		q += " AND start_time >= ?"
		args = append(args, f.Since.Unix())
	}
	if f.Until != nil {
		q += " AND start_time <= ?"
		args = append(args, f.Until.Unix())
	}
	q += " ORDER BY start_time DESC"
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += " LIMIT ?"
	args = append(args, f.Limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Event{} // non-nil so an empty result marshals as [] not null
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetByIDs returns the events with the given ids keyed by id. Missing ids are
// simply absent from the map (e.g. a Frigate semantic-search hit for an event
// the gateway never mirrored). The caller preserves relevance/order; this only
// hydrates. No camera-scope filtering here — callers do that before/after.
func (s *Store) GetByIDs(ctx context.Context, ids []string) (map[string]Event, error) {
	out := make(map[string]Event, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	q := `SELECT ` + eventColumns + ` FROM events WHERE id IN (` + placeholders(len(ids)) + `)`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out[e.ID] = e
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, id string) (*Event, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+eventColumns+` FROM events WHERE id = ?`, id)
	e, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &e, nil
}

// SetKeepClip pins (or unpins) an event's clip so the cache pruner skips it.
// Returns false if no event with that id exists.
func (s *Store) SetKeepClip(ctx context.Context, id string, keep bool) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE events SET keep_clip = ?, updated_at = ? WHERE id = ?`,
		boolToInt(keep), time.Now().Unix(), id,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func nullStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// placeholders returns "?, ?, ..." with n placeholders for an IN clause.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fromUnixFloat(f float64) time.Time {
	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}
