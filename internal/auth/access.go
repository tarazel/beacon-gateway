package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// usersByEmail selects every account tied to an email, whether it's the account's
// own address or the address on one of its linked identities.
const usersByEmail = `SELECT id FROM users WHERE LOWER(email) = ?1
	UNION SELECT user_id FROM user_identities WHERE LOWER(email) = ?1`

// IsUserActive reports whether the account exists and has not been disabled.
func (s *Store) IsUserActive(ctx context.Context, userID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM users WHERE id = ? AND disabled_at IS NULL`, userID).Scan(&n)
	return n > 0, err
}

// IsEmailRevoked reports whether access was revoked for this email.
func (s *Store) IsEmailRevoked(ctx context.Context, email string) (bool, error) {
	email = canonicalEmail(email)
	if email == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM revoked_emails WHERE email = ?`, email).Scan(&n)
	return n > 0, err
}

// Revocation summarizes what RevokeAccess changed.
type Revocation struct {
	Allowlisted bool // an allowlist row was removed
	Users       int  // accounts disabled
	Tokens      int  // refresh tokens revoked
	Devices     int  // push registrations removed
}

// RevokeAccess removes an email from the allowlist, blocks it from signing in,
// and disables every account tied to it: refresh tokens are revoked, push
// registrations deleted, and tokens already issued stop working.
func (s *Store) RevokeAccess(ctx context.Context, email string) (Revocation, error) {
	var out Revocation
	email = canonicalEmail(email)
	if email == "" {
		return out, errors.New("email required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	exec := func(query string, args ...any) (int, error) {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		return int(n), err
	}

	n, err := exec(`DELETE FROM allowed_emails WHERE email = ?`, email)
	if err != nil {
		return out, err
	}
	out.Allowlisted = n > 0
	if _, err := exec(`INSERT INTO revoked_emails (email, revoked_at) VALUES (?, ?)
		ON CONFLICT(email) DO UPDATE SET revoked_at = excluded.revoked_at`, email, now); err != nil {
		return out, err
	}
	if out.Tokens, err = exec(`UPDATE refresh_tokens SET revoked_at = ?2
		WHERE revoked_at IS NULL AND user_id IN (`+usersByEmail+`)`, email, now); err != nil {
		return out, err
	}
	if out.Devices, err = exec(`DELETE FROM devices WHERE user_id IN (`+usersByEmail+`)`, email); err != nil {
		return out, err
	}
	if out.Users, err = exec(`UPDATE users SET disabled_at = ?2 WHERE id IN (`+usersByEmail+`)`, email, now); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// restoreAccess undoes RevokeAccess for an email (accounts stay signed out).
func restoreAccess(ctx context.Context, tx *sql.Tx, email string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM revoked_emails WHERE email = ?`, email); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = NULL WHERE id IN (`+usersByEmail+`)`, email)
	return err
}
