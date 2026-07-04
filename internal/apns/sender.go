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
	// Zones + Score are not sent in the payload; they feed per-user rule
	// evaluation (see Ruler) so a member can filter by zone or minimum score.
	Zones []string
	Score float64
}

// Ruler decides, per user, whether an event should notify them — the per-user
// notification rules (label / zone / min-score / quiet-hours / cooldown) applied
// AFTER camera scope + mute and BEFORE delivery. A nil Ruler on the Sender means
// no rule filtering (every eligible device is notified). Allows may have a side
// effect (recording cooldown), so the Sender calls it exactly once per user.
type Ruler interface {
	Allows(ctx context.Context, userID string, ev RuleEvent) bool
}

// RuleEvent is the event data a Ruler evaluates against.
type RuleEvent struct {
	Camera string
	Label  string
	Zones  []string
	Score  float64
}

// Sender selects which devices should receive a push (mute + per-camera scope),
// builds the payload, and hands delivery to a Transport. A nil transport means
// push is not configured and SendToAll is a no-op.
type Sender struct {
	transport Transport
	db        *sql.DB
	log       *slog.Logger
	sandbox   bool
	ruler     Ruler
}

// NewSender wires a Sender to a delivery Transport (DirectTransport or
// RelayTransport) and an optional per-user Ruler. transport may be nil, in which
// case pushes are skipped; ruler may be nil, in which case no rule filtering is
// applied (every eligible device is notified).
func NewSender(transport Transport, db *sql.DB, ruler Ruler, sandbox bool, log *slog.Logger) *Sender {
	if transport == nil {
		log.Warn("apns: no transport configured, pushes will be skipped")
	}
	return &Sender{transport: transport, db: db, ruler: ruler, log: log, sandbox: sandbox}
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
		SELECT u.id, d.id, d.apns_token, d.platform
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

	// Group tokens by user so per-user notification rules can be applied once per
	// user (scope + mute are already enforced by the query above).
	// Group tokens by user so per-user notification rules can be applied once per
	// user (scope + mute are already enforced by the query above). Track each
	// token's platform so we can route it to the right push backend (APNs/FCM).
	tokenToID := make(map[string]string)
	tokenPlatform := make(map[string]string)
	userTokens := make(map[string][]string)
	var userOrder []string
	for rows.Next() {
		var userID, id, tok, platform string
		if err := rows.Scan(&userID, &id, &tok, &platform); err != nil {
			return err
		}
		if platform == "" {
			platform = "ios"
		}
		tokenToID[tok] = id
		tokenPlatform[tok] = platform
		if _, seen := userTokens[userID]; !seen {
			userOrder = append(userOrder, userID)
		}
		userTokens[userID] = append(userTokens[userID], tok)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(userTokens) == 0 {
		s.log.Info("apns: no registered devices", "event_id", n.EventID)
		return nil
	}

	// Apply each user's notification rules (label/zone/score/quiet-hours/cooldown),
	// then bucket the surviving tokens by platform. A user filtered out here never
	// reaches the relay/APNs.
	ruleEv := RuleEvent{Camera: n.Camera, Label: n.Label, Zones: n.Zones, Score: n.Score}
	byPlatform := make(map[string][]string)
	var totalTokens, filteredUsers int
	for _, userID := range userOrder {
		if s.ruler != nil && !s.ruler.Allows(ctx, userID, ruleEv) {
			filteredUsers++
			continue
		}
		for _, tok := range userTokens[userID] {
			p := tokenPlatform[tok]
			byPlatform[p] = append(byPlatform[p], tok)
			totalTokens++
		}
	}

	if totalTokens == 0 {
		s.log.Info("apns: all recipients filtered by notification rules", "event_id", n.EventID, "camera", n.Camera, "users_filtered", filteredUsers)
		return nil
	}
	if filteredUsers > 0 {
		s.log.Info("apns: some recipients filtered by notification rules", "event_id", n.EventID, "users_filtered", filteredUsers)
	}

	// The transport renders the payload: DirectTransport builds the rich payload,
	// RelayTransport the privacy-minimal one (event_id only). See Transport.BuildPayload.
	// NOTE: this is the APNs payload shape. FCM (Android) needs its own payload —
	// that translation lands with the FCM pusher in P2.9(b); today all devices are iOS.
	env := "production"
	if s.sandbox {
		env = "sandbox"
	}

	// Deliver per platform so each bucket routes to the right backend (iOS→APNs,
	// Android→FCM via the relay). Payloads are platform-specific (APNs JSON vs FCM
	// data), so build per bucket.
	var results []Result
	for platform, toks := range byPlatform {
		payloadBytes, berr := s.transport.BuildPayload(platform, n)
		if berr != nil {
			return fmt.Errorf("build payload (platform %s): %w", platform, berr)
		}
		res, derr := s.transport.Deliver(ctx, platform, env, toks, payloadBytes)
		if derr != nil {
			// A lapsed subscription drops the whole household's pushes. Never let that
			// be silent — log it loudly and distinctly (the app surfaces the same state
			// via GET /api/subscription). The caller still gets the sentinel.
			if errors.Is(derr, ErrSubscriptionInactive) {
				s.log.Warn("PUSH DROPPED: Beacon Pro subscription inactive — the relay is refusing pushes for this household; renew to restore notifications",
					"reason", "subscription_inactive",
					"devices_dropped", totalTokens,
					"camera", n.Camera,
					"event_id", n.EventID)
				return derr
			}
			return fmt.Errorf("deliver via %s (platform %s): %w", s.transport.Name(), platform, derr)
		}
		results = append(results, res...)
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
