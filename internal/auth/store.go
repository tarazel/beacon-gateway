package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Identity providers. A user may have one linked identity per provider (Apple on
// their iPhone, Google on their Samsung), all resolving to the same account.
const (
	ProviderApple  = "apple"
	ProviderGoogle = "google"
)

type User struct {
	ID        string
	AppleSub  string
	Email     string
	Name      string
	Role      string
	CreatedAt time.Time
}

func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// SetMutedUntil sets the user's alert-mute expiry, or clears it when until is nil.
func (s *Store) SetMutedUntil(ctx context.Context, userID string, until *time.Time) error {
	if until == nil {
		_, err := s.db.ExecContext(ctx, `UPDATE users SET muted_until = NULL WHERE id = ?`, userID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET muted_until = ? WHERE id = ?`, until.Unix(), userID)
	return err
}

// MutedUntil returns the user's active mute expiry, or nil if not muted / expired.
func (s *Store) MutedUntil(ctx context.Context, userID string) (*time.Time, error) {
	var ts sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT muted_until FROM users WHERE id = ?`, userID).Scan(&ts); err != nil {
		return nil, err
	}
	if !ts.Valid {
		return nil, nil
	}
	t := time.Unix(ts.Int64, 0).UTC()
	if !t.After(time.Now()) {
		return nil, nil // expired
	}
	return &t, nil
}

// SetCameraMute mutes a single camera's alerts for the user until `until`, or
// clears that camera's mute when until is nil.
func (s *Store) SetCameraMute(ctx context.Context, userID, camera string, until *time.Time) error {
	if until == nil {
		_, err := s.db.ExecContext(ctx, `DELETE FROM camera_mutes WHERE user_id = ? AND camera = ?`, userID, camera)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO camera_mutes (user_id, camera, muted_until) VALUES (?, ?, ?)
		ON CONFLICT(user_id, camera) DO UPDATE SET muted_until = excluded.muted_until
	`, userID, camera, until.Unix())
	return err
}

// CameraMutes returns the user's active (unexpired) per-camera mute expiries,
// keyed by camera id.
func (s *Store) CameraMutes(ctx context.Context, userID string) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT camera, muted_until FROM camera_mutes WHERE user_id = ? AND muted_until > ?`,
		userID, time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var camera string
		var ts int64
		if err := rows.Scan(&camera, &ts); err != nil {
			return nil, err
		}
		out[camera] = time.Unix(ts, 0).UTC()
	}
	return out, rows.Err()
}

func (s *Store) GetUserByAppleSub(ctx context.Context, appleSub string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, apple_sub, email, name, role, created_at FROM users WHERE apple_sub = ?`, appleSub)
	var u User
	var createdAt int64
	var emailNS, nameNS sql.NullString
	if err := row.Scan(&u.ID, &u.AppleSub, &emailNS, &nameNS, &u.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.Email = emailNS.String
	u.Name = nameNS.String
	u.CreatedAt = time.Unix(createdAt, 0)
	return &u, nil
}

// FindOrCreateUser creates (or returns) a user keyed by an Apple sub. Retained for
// the admin CLI's local dev-user path; real Apple/Google sign-in goes through the
// provider-aware methods below. New users also get an 'apple' row in
// user_identities so the identities table stays the complete source of truth.
func (s *Store) FindOrCreateUser(ctx context.Context, appleSub, email, name, role string) (*User, error) {
	if existing, err := s.GetUserByAppleSub(ctx, appleSub); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	return s.CreateUserWithIdentity(ctx, ProviderApple, appleSub, appleSub, email, name, role)
}

// GetUserByProviderIdentity returns the user linked to (provider, sub), or nil if
// no such identity is on file. This is the primary sign-in lookup.
func (s *Store) GetUserByProviderIdentity(ctx context.Context, provider, sub string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.apple_sub, u.email, u.name, u.role, u.created_at
		FROM user_identities i JOIN users u ON u.id = i.user_id
		WHERE i.provider = ? AND i.provider_sub = ?`, provider, sub)
	var u User
	var createdAt int64
	var emailNS, nameNS sql.NullString
	if err := row.Scan(&u.ID, &u.AppleSub, &emailNS, &nameNS, &u.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.Email = emailNS.String
	u.Name = nameNS.String
	u.CreatedAt = time.Unix(createdAt, 0)
	return &u, nil
}

// GetUserByEmail returns a user whose (case-insensitive) email matches, or nil.
// Used for cross-provider account linking: a Google sign-in whose verified email
// matches an existing Apple user is treated as the same person.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	email = canonicalEmail(email)
	if email == "" {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, apple_sub, email, name, role, created_at FROM users WHERE LOWER(email) = ?`, email)
	var u User
	var createdAt int64
	var emailNS, nameNS sql.NullString
	if err := row.Scan(&u.ID, &u.AppleSub, &emailNS, &nameNS, &u.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.Email = emailNS.String
	u.Name = nameNS.String
	u.CreatedAt = time.Unix(createdAt, 0)
	return &u, nil
}

// LinkIdentity attaches (provider, sub) to an existing user. Idempotent: a repeat
// link of the same identity to the same user is a no-op. If the identity is already
// bound to a DIFFERENT user, it is left untouched and no error is returned (the
// existing binding wins — we never silently move an identity between accounts).
func (s *Store) LinkIdentity(ctx context.Context, userID, provider, sub, email string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_identities (provider, provider_sub, user_id, email, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(provider, provider_sub) DO NOTHING`,
		provider, sub, userID, nullable(email), time.Now().Unix(),
	)
	return err
}

// CreateUserWithIdentity creates a brand-new user with one linked identity, in a
// single transaction. legacyAppleSub fills the NOT NULL users.apple_sub anchor: it
// is the real Apple sub for Apple sign-ins, and a synthetic "google:<sub>" value
// for other providers (see the 0009 migration note).
func (s *Store) CreateUserWithIdentity(ctx context.Context, provider, sub, legacyAppleSub, email, name, role string) (*User, error) {
	if role != RoleAdmin {
		role = RoleMember
	}
	if legacyAppleSub == "" {
		legacyAppleSub = provider + ":" + sub
	}
	u := User{
		ID:        uuid.NewString(),
		AppleSub:  legacyAppleSub,
		Email:     email,
		Name:      name,
		Role:      role,
		CreatedAt: time.Now(),
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (id, apple_sub, email, name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.AppleSub, nullable(u.Email), nullable(u.Name), u.Role, u.CreatedAt.Unix(),
	); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_identities (provider, provider_sub, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)`,
		provider, sub, u.ID, nullable(email), u.CreatedAt.Unix(),
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &u, nil
}

// CountUsers returns the number of registered users. Used to bootstrap the
// first user as admin (the instance owner).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

// SetUserRole sets a user's role. role must be RoleAdmin or RoleMember.
func (s *Store) SetUserRole(ctx context.Context, userID, role string) error {
	if role != RoleAdmin && role != RoleMember {
		return errors.New("role must be 'admin' or 'member'")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("user not found")
	}
	return nil
}

// AccessibleCameras reports which cameras a user may see. all=true means
// unrestricted (admins, and members with no explicit scope). Otherwise cams is
// the exact set the member is scoped to (possibly empty = sees nothing).
func (s *Store) AccessibleCameras(ctx context.Context, userID string) (cams []string, all bool, err error) {
	var role string
	if err := s.db.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, userID).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if role == RoleAdmin {
		return nil, true, nil
	}
	cams, err = s.GetUserCameras(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	if len(cams) == 0 {
		return nil, true, nil // unscoped member sees all (household default)
	}
	return cams, false, nil
}

// GetUserCameras returns the explicit per-camera grants for a user (empty = unscoped).
func (s *Store) GetUserCameras(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT camera FROM user_cameras WHERE user_id = ? ORDER BY camera`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetUserCameras replaces a user's camera scope. An empty/nil list clears the
// scope, returning the user to the unscoped (sees-all) default.
func (s *Store) SetUserCameras(ctx context.Context, userID string, cameras []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_cameras WHERE user_id = ?`, userID); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(cameras))
	for _, c := range cameras {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_cameras (user_id, camera) VALUES (?, ?)`, userID, c); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, apple_sub, email, name, role, created_at FROM users WHERE id = ?`, id)
	var u User
	var createdAt int64
	var emailNS, nameNS sql.NullString
	if err := row.Scan(&u.ID, &u.AppleSub, &emailNS, &nameNS, &u.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.Email = emailNS.String
	u.Name = nameNS.String
	u.CreatedAt = time.Unix(createdAt, 0)
	return &u, nil
}

type RefreshToken struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

func (s *Store) IssueRefreshToken(ctx context.Context, userID string, ttl time.Duration) (raw string, tok *RefreshToken, err error) {
	raw, err = randomToken(32)
	if err != nil {
		return "", nil, err
	}
	tok = &RefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl),
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		tok.ID, userID, hashToken(raw), tok.ExpiresAt.Unix(), time.Now().Unix(),
	)
	if err != nil {
		return "", nil, err
	}
	return raw, tok, nil
}

func (s *Store) ConsumeRefreshToken(ctx context.Context, raw string) (*RefreshToken, error) {
	hash := hashToken(raw)
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, expires_at FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL`, hash)
	var tok RefreshToken
	var expires int64
	if err := row.Scan(&tok.ID, &tok.UserID, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("refresh token not found or revoked")
		}
		return nil, err
	}
	tok.ExpiresAt = time.Unix(expires, 0)
	if time.Now().After(tok.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}
	return &tok, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

type AllowedEmail struct {
	Email   string
	Note    string
	AddedAt time.Time
}

func (s *Store) AllowEmail(ctx context.Context, email, note string) error {
	email = canonicalEmail(email)
	if email == "" {
		return errors.New("email required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO allowed_emails (email, note, added_at) VALUES (?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET note = excluded.note`,
		email, nullable(note), time.Now().Unix(),
	)
	return err
}

func (s *Store) RevokeEmail(ctx context.Context, email string) (bool, error) {
	email = canonicalEmail(email)
	if email == "" {
		return false, errors.New("email required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM allowed_emails WHERE email = ?`, email)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ListAllowedEmails(ctx context.Context) ([]AllowedEmail, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, note, added_at FROM allowed_emails ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AllowedEmail
	for rows.Next() {
		var a AllowedEmail
		var note sql.NullString
		var addedAt int64
		if err := rows.Scan(&a.Email, &note, &addedAt); err != nil {
			return nil, err
		}
		a.Note = note.String
		a.AddedAt = time.Unix(addedAt, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) IsEmailAllowed(ctx context.Context, email string) (bool, error) {
	email = canonicalEmail(email)
	if email == "" {
		return false, nil
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM allowed_emails WHERE email = ?`, email).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, apple_sub, email, name, role, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var emailNS, nameNS sql.NullString
		var createdAt int64
		if err := rows.Scan(&u.ID, &u.AppleSub, &emailNS, &nameNS, &u.Role, &createdAt); err != nil {
			return nil, err
		}
		u.Email = emailNS.String
		u.Name = nameNS.String
		u.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

// FindUserByIDOrEmail looks up a user by ID first, then falls back to email match.
func (s *Store) FindUserByIDOrEmail(ctx context.Context, idOrEmail string) (*User, error) {
	if u, err := s.GetUser(ctx, idOrEmail); err != nil {
		return nil, err
	} else if u != nil {
		return u, nil
	}
	email := canonicalEmail(idOrEmail)
	if email == "" {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, apple_sub, email, name, role, created_at FROM users WHERE LOWER(email) = ?`, email)
	var u User
	var emailNS, nameNS sql.NullString
	var createdAt int64
	if err := row.Scan(&u.ID, &u.AppleSub, &emailNS, &nameNS, &u.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.Email = emailNS.String
	u.Name = nameNS.String
	u.CreatedAt = time.Unix(createdAt, 0)
	return &u, nil
}

// DeleteUser removes a user and cascades to their devices and refresh tokens.
// Returns the counts of removed devices and refresh tokens.
func (s *Store) DeleteUser(ctx context.Context, userID string) (devices int, tokens int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM devices WHERE user_id = ?`, userID).Scan(&devices); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM refresh_tokens WHERE user_id = ?`, userID).Scan(&tokens); err != nil {
		return 0, 0, err
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return 0, 0, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, 0, errors.New("user not found")
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return devices, tokens, nil
}

func (s *Store) RevokeAllRefreshTokens(ctx context.Context, userID string) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		time.Now().Unix(), userID,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func canonicalEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
