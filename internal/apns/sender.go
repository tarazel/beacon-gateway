package apns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

type Notification struct {
	Title       string
	Body        string
	ThreadID    string
	EventID     string
	Camera      string
	Label       string
	SnapshotURL string
}

// Sender selects which devices should receive a push (mute + per-camera scope),
// builds the payload, and hands delivery to a Transport. A nil transport means
// push is not configured and SendToAll is a no-op.
type Sender struct {
	transport Transport
	db        *sql.DB
	log       *slog.Logger
	sandbox   bool
}

// NewSender wires a Sender to a delivery Transport (DirectTransport or
// RelayTransport). transport may be nil, in which case pushes are skipped.
func NewSender(transport Transport, db *sql.DB, sandbox bool, log *slog.Logger) *Sender {
	if transport == nil {
		log.Warn("apns: no transport configured, pushes will be skipped")
	}
	return &Sender{transport: transport, db: db, log: log, sandbox: sandbox}
}

func (s *Sender) SendToAll(ctx context.Context, n Notification) error {
	if s.transport == nil {
		s.log.Info("apns skipped (not configured)", "event_id", n.EventID, "camera", n.Camera, "label", n.Label)
		return nil
	}

	// Push only to devices whose user (a) hasn't muted alerts globally
	// (users.muted_until) or for this camera (camera_mutes), and (b) may access
	// this camera: admins and unscoped members (no user_cameras rows) see all;
	// a scoped member must have a row for this camera.
	now := time.Now().Unix()
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.apns_token
		FROM devices d
		JOIN users u ON u.id = d.user_id
		WHERE (u.muted_until IS NULL OR u.muted_until <= ?)
		  AND NOT EXISTS (
		      SELECT 1 FROM camera_mutes cm
		      WHERE cm.user_id = u.id AND cm.camera = ? AND cm.muted_until > ?
		  )
		  AND (
		      u.role = 'admin'
		      OR NOT EXISTS (SELECT 1 FROM user_cameras uc WHERE uc.user_id = u.id)
		      OR EXISTS (SELECT 1 FROM user_cameras uc WHERE uc.user_id = u.id AND uc.camera = ?)
		  )
	`, now, n.Camera, now, n.Camera)
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	tokenToID := make(map[string]string)
	var deviceTokens []string
	for rows.Next() {
		var id, tok string
		if err := rows.Scan(&id, &tok); err != nil {
			return err
		}
		tokenToID[tok] = id
		deviceTokens = append(deviceTokens, tok)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(deviceTokens) == 0 {
		s.log.Info("apns: no registered devices", "event_id", n.EventID)
		return nil
	}

	payloadBytes, err := buildPayload(n)
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}

	env := "production"
	if s.sandbox {
		env = "sandbox"
	}

	results, err := s.transport.Deliver(ctx, env, deviceTokens, payloadBytes)
	if err != nil {
		return fmt.Errorf("deliver via %s: %w", s.transport.Name(), err)
	}

	var errs []string
	for _, r := range results {
		switch r.Status {
		case StatusSent:
			s.log.Info("apns sent", "device_id", tokenToID[r.DeviceToken], "event_id", n.EventID, "transport", s.transport.Name())
		case StatusUnregistered:
			id := tokenToID[r.DeviceToken]
			s.log.Warn("apns: pruning unregistered device", "device_id", id, "reason", r.Reason)
			if _, derr := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id); derr != nil {
				s.log.Warn("apns: failed to prune unregistered device", "device_id", id, "err", derr)
			}
		default: // StatusError
			errs = append(errs, fmt.Sprintf("device %s: %s", tokenToID[r.DeviceToken], r.Reason))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
