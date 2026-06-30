package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type Invite struct {
	Code       string     `json:"code"`
	Role       string     `json:"role"`
	Cameras    []string   `json:"cameras"` // empty = all cameras
	Note       string     `json:"note,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ConsumedBy string     `json:"consumed_by,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// Pending reports whether the invite can still be redeemed.
func (i *Invite) Pending() bool {
	if i.ConsumedAt != nil {
		return false
	}
	if i.ExpiresAt != nil && !i.ExpiresAt.After(time.Now()) {
		return false
	}
	return true
}

// inviteCodeAlphabet omits ambiguous characters (0/O, 1/I/L) so codes are easy
// to read aloud and type.
const inviteCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewInviteCode returns a random human-typeable invite code, e.g. "K7P2-Q9MR".
func NewInviteCode() (string, error) {
	const n = 8
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, n+1)
	for i, x := range b {
		if i == n/2 {
			out = append(out, '-')
		}
		out = append(out, inviteCodeAlphabet[int(x)%len(inviteCodeAlphabet)])
	}
	return string(out), nil
}

// CreateInvite stores a new invite. cameras may be nil (scopes to all cameras).
func (s *Store) CreateInvite(ctx context.Context, code, role string, cameras []string, note, createdBy string, expiresAt *time.Time) (*Invite, error) {
	if role != RoleAdmin && role != RoleMember {
		role = RoleMember
	}
	inv := &Invite{
		Code:      code,
		Role:      role,
		Cameras:   cameras,
		Note:      note,
		CreatedBy: createdBy,
		CreatedAt: time.Now().Truncate(time.Second).UTC(),
		ExpiresAt: expiresAt,
	}
	var camsJSON any
	if len(cameras) > 0 {
		b, _ := json.Marshal(cameras)
		camsJSON = string(b)
	}
	var exp any
	if expiresAt != nil {
		exp = expiresAt.Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (code, role, cameras, note, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		code, role, camsJSON, nullable(note), nullable(createdBy), inv.CreatedAt.Unix(), exp,
	)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func scanInvite(row interface{ Scan(...any) error }) (*Invite, error) {
	var inv Invite
	var camsNS, noteNS, createdByNS, consumedByNS sql.NullString
	var createdAt int64
	var expiresNS, consumedNS sql.NullInt64
	if err := row.Scan(&inv.Code, &inv.Role, &camsNS, &noteNS, &createdByNS, &createdAt, &expiresNS, &consumedByNS, &consumedNS); err != nil {
		return nil, err
	}
	if camsNS.Valid && camsNS.String != "" {
		_ = json.Unmarshal([]byte(camsNS.String), &inv.Cameras)
	}
	inv.Note = noteNS.String
	inv.CreatedBy = createdByNS.String
	inv.CreatedAt = time.Unix(createdAt, 0).UTC()
	if expiresNS.Valid {
		t := time.Unix(expiresNS.Int64, 0).UTC()
		inv.ExpiresAt = &t
	}
	inv.ConsumedBy = consumedByNS.String
	if consumedNS.Valid {
		t := time.Unix(consumedNS.Int64, 0).UTC()
		inv.ConsumedAt = &t
	}
	return &inv, nil
}

const inviteCols = `code, role, cameras, note, created_by, created_at, expires_at, consumed_by, consumed_at`

func (s *Store) GetInvite(ctx context.Context, code string) (*Invite, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+inviteCols+` FROM invites WHERE code = ?`, code)
	inv, err := scanInvite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return inv, err
}

func (s *Store) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+inviteCols+` FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

func (s *Store) DeleteInvite(ctx context.Context, code string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE code = ?`, code)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ConsumeInvite marks an invite consumed by userID, but only if it is still
// pending (unconsumed and unexpired). Returns false if it was already used,
// expired, or unknown — enforcing single use even under a race.
func (s *Store) ConsumeInvite(ctx context.Context, code, userID string) (bool, error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET consumed_by = ?, consumed_at = ?
		 WHERE code = ? AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		userID, now.Unix(), code, now.Unix(),
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
