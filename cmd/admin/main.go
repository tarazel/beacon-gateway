package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hydak/beacon-gateway/internal/auth"
	"github.com/hydak/beacon-gateway/internal/db"
)

const usageText = `beacon admin

Usage: beacon-admin [--db <path>] <command> [args]

Commands:
  allow <email> [--note <text>]      add an email to the allowlist
  revoke <email>                     remove an email from the allowlist
  list-allowed                       list allowlisted emails
  list-users                         list registered users (with role + camera scope)
  set-role <id-or-email> <role>      set a user's role: admin or member
  set-cameras <id-or-email> [cam..]  scope a user to cameras (no cameras = sees all)
  delete-user <id-or-email>          delete a user (cascades to devices + tokens)
  invite create [opts]               mint an invite code (opts below)
  invite list                        list invites (pending + used)
  invite delete <code>               revoke an invite
  create-user <email> [opts]         create a test user without Apple (opts below)
  token <id-or-email> [--ttl <dur>]  mint a JWT for an existing user (testing)
  help                               show this message

invite create options:
  --role <admin|member>   role for the invitee (default: member)
  --camera <id>           scope to a camera (repeatable; omit = all cameras)
  --note <text>           free-text note
  --expires <duration>    e.g. 168h, 30m (omit = never expires)

create-user options:
  --name <text>           display name
  --role <admin|member>   role (default: member)

Env:
  DB_PATH           path to sqlite db (default: data/beacon.db; --db overrides)
  JWT_SIGNING_KEY   required by 'token'; must match the running gateway's key
`

func main() {
	dbPath := envOr("DB_PATH", "data/beacon.db")

	// Pre-parse: pull --db out before subcommand dispatch.
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--db" && i+1 < len(args) {
			dbPath = args[i+1]
			args = append(args[:i], args[i+2:]...)
			i--
		} else if strings.HasPrefix(args[i], "--db=") {
			dbPath = strings.TrimPrefix(args[i], "--db=")
			args = append(args[:i], args[i+1:]...)
			i--
		}
	}

	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	cmd := args[0]
	rest := args[1:]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := db.Open(ctx, dbPath)
	if err != nil {
		fatal("open db: %v", err)
	}
	defer database.Close()

	store := auth.NewStore(database)

	switch cmd {
	case "allow":
		cmdAllow(ctx, store, rest)
	case "revoke":
		cmdRevoke(ctx, store, rest)
	case "list-allowed":
		cmdListAllowed(ctx, store)
	case "list-users":
		cmdListUsers(ctx, store)
	case "set-role":
		cmdSetRole(ctx, store, rest)
	case "set-cameras":
		cmdSetCameras(ctx, store, rest)
	case "invite":
		cmdInvite(ctx, store, rest)
	case "create-user":
		cmdCreateUser(ctx, store, rest)
	case "token":
		cmdToken(ctx, store, rest)
	case "delete-user":
		cmdDeleteUser(ctx, store, rest)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usageText)
		os.Exit(2)
	}
}

func cmdAllow(ctx context.Context, store *auth.Store, args []string) {
	var email, note string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--note":
			if i+1 >= len(args) {
				fatal("--note requires a value")
			}
			note = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--note="):
			note = strings.TrimPrefix(args[i], "--note=")
		case strings.HasPrefix(args[i], "-"):
			fatal("unknown flag: %s", args[i])
		case email == "":
			email = args[i]
		default:
			fatal("unexpected argument: %s", args[i])
		}
	}
	if email == "" {
		fatal("usage: allow <email> [--note <text>]")
	}
	if err := store.AllowEmail(ctx, email, note); err != nil {
		fatal("allow: %v", err)
	}
	fmt.Printf("allowed: %s\n", strings.ToLower(strings.TrimSpace(email)))
}

func cmdRevoke(ctx context.Context, store *auth.Store, args []string) {
	if len(args) != 1 {
		fatal("usage: revoke <email>")
	}
	email := args[0]
	existed, err := store.RevokeEmail(ctx, email)
	if err != nil {
		fatal("revoke: %v", err)
	}
	if !existed {
		fmt.Printf("not in allowlist: %s\n", strings.ToLower(strings.TrimSpace(email)))
		return
	}

	// Revoke active sessions for any user with that email.
	if u, err := store.FindUserByIDOrEmail(ctx, email); err == nil && u != nil {
		if n, err := store.RevokeAllRefreshTokens(ctx, u.ID); err == nil && n > 0 {
			fmt.Printf("revoked %s (also revoked %d active refresh tokens for user %s)\n", email, n, u.ID)
			return
		}
	}
	fmt.Printf("revoked: %s\n", strings.ToLower(strings.TrimSpace(email)))
}

func cmdListAllowed(ctx context.Context, store *auth.Store) {
	rows, err := store.ListAllowedEmails(ctx)
	if err != nil {
		fatal("list-allowed: %v", err)
	}
	if len(rows) == 0 {
		fmt.Println("(allowlist empty — APPLE_ALLOWED_EMAILS env may still grant access)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tADDED\tNOTE")
	for _, a := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Email, a.AddedAt.Format(time.RFC3339), a.Note)
	}
	tw.Flush()
}

func cmdListUsers(ctx context.Context, store *auth.Store) {
	users, err := store.ListUsers(ctx)
	if err != nil {
		fatal("list-users: %v", err)
	}
	if len(users) == 0 {
		fmt.Println("(no users)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tEMAIL\tNAME\tROLE\tCAMERAS\tCREATED")
	for _, u := range users {
		scope := "(all)"
		if cams, err := store.GetUserCameras(ctx, u.ID); err == nil && len(cams) > 0 {
			scope = strings.Join(cams, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", u.ID, u.Email, u.Name, u.Role, scope, u.CreatedAt.Format(time.RFC3339))
	}
	tw.Flush()
}

func cmdSetRole(ctx context.Context, store *auth.Store, args []string) {
	if len(args) != 2 {
		fatal("usage: set-role <id-or-email> <admin|member>")
	}
	role := strings.ToLower(args[1])
	if role != auth.RoleAdmin && role != auth.RoleMember {
		fatal("role must be 'admin' or 'member'")
	}
	u, err := store.FindUserByIDOrEmail(ctx, args[0])
	if err != nil {
		fatal("lookup: %v", err)
	}
	if u == nil {
		fatal("user not found: %s", args[0])
	}
	if err := store.SetUserRole(ctx, u.ID, role); err != nil {
		fatal("set-role: %v", err)
	}
	fmt.Printf("set role of %s (%s) to %s\n", u.ID, u.Email, role)
}

func cmdSetCameras(ctx context.Context, store *auth.Store, args []string) {
	if len(args) < 1 {
		fatal("usage: set-cameras <id-or-email> [camera ...]   (no cameras = sees all)")
	}
	u, err := store.FindUserByIDOrEmail(ctx, args[0])
	if err != nil {
		fatal("lookup: %v", err)
	}
	if u == nil {
		fatal("user not found: %s", args[0])
	}
	cams := args[1:]
	if err := store.SetUserCameras(ctx, u.ID, cams); err != nil {
		fatal("set-cameras: %v", err)
	}
	if len(cams) == 0 {
		fmt.Printf("cleared camera scope for %s (%s) — now sees all cameras\n", u.ID, u.Email)
		return
	}
	fmt.Printf("scoped %s (%s) to cameras: %s\n", u.ID, u.Email, strings.Join(cams, ", "))
}

func cmdInvite(ctx context.Context, store *auth.Store, args []string) {
	if len(args) == 0 {
		fatal("usage: invite <create|list|delete> ...")
	}
	switch args[0] {
	case "create":
		cmdInviteCreate(ctx, store, args[1:])
	case "list":
		cmdInviteList(ctx, store)
	case "delete", "revoke":
		if len(args) != 2 {
			fatal("usage: invite delete <code>")
		}
		existed, err := store.DeleteInvite(ctx, strings.ToUpper(strings.TrimSpace(args[1])))
		if err != nil {
			fatal("invite delete: %v", err)
		}
		if !existed {
			fmt.Printf("no such invite: %s\n", args[1])
			return
		}
		fmt.Printf("deleted invite %s\n", strings.ToUpper(args[1]))
	default:
		fatal("unknown invite subcommand: %s", args[0])
	}
}

func cmdInviteCreate(ctx context.Context, store *auth.Store, args []string) {
	role := auth.RoleMember
	var cameras []string
	var note string
	var expiresAt *time.Time
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 >= len(args) {
				fatal("%s requires a value", a)
			}
			i++
			return args[i]
		}
		switch {
		case a == "--role":
			role = strings.ToLower(next())
		case a == "--camera":
			cameras = append(cameras, next())
		case a == "--note":
			note = next()
		case a == "--expires":
			d, err := time.ParseDuration(next())
			if err != nil {
				fatal("invalid --expires duration: %v", err)
			}
			t := time.Now().Add(d).Truncate(time.Second).UTC()
			expiresAt = &t
		default:
			fatal("unknown flag: %s", a)
		}
	}
	if role != auth.RoleAdmin && role != auth.RoleMember {
		fatal("role must be 'admin' or 'member'")
	}
	code, err := auth.NewInviteCode()
	if err != nil {
		fatal("generate code: %v", err)
	}
	inv, err := store.CreateInvite(ctx, code, role, cameras, note, "", expiresAt)
	if err != nil {
		fatal("create invite: %v", err)
	}
	scope := "all cameras"
	if len(inv.Cameras) > 0 {
		scope = strings.Join(inv.Cameras, ", ")
	}
	exp := "never"
	if inv.ExpiresAt != nil {
		exp = inv.ExpiresAt.Format(time.RFC3339)
	}
	fmt.Printf("invite code: %s\n  role:    %s\n  cameras: %s\n  expires: %s\n", inv.Code, inv.Role, scope, exp)
}

func cmdInviteList(ctx context.Context, store *auth.Store) {
	invites, err := store.ListInvites(ctx)
	if err != nil {
		fatal("invite list: %v", err)
	}
	if len(invites) == 0 {
		fmt.Println("(no invites)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CODE\tROLE\tCAMERAS\tSTATUS\tEXPIRES\tNOTE")
	for _, inv := range invites {
		scope := "(all)"
		if len(inv.Cameras) > 0 {
			scope = strings.Join(inv.Cameras, ",")
		}
		status := "pending"
		if inv.ConsumedAt != nil {
			status = "used"
		} else if !inv.Pending() {
			status = "expired"
		}
		exp := "never"
		if inv.ExpiresAt != nil {
			exp = inv.ExpiresAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", inv.Code, inv.Role, scope, status, exp, inv.Note)
	}
	tw.Flush()
}

// cmdCreateUser makes a user without Sign in with Apple, for local testing.
// It uses a synthetic apple_sub ("dev:<email>") so a later real Apple sign-in
// with the same address would create a separate account — fine for throwaway DBs.
func cmdCreateUser(ctx context.Context, store *auth.Store, args []string) {
	var email, name string
	role := auth.RoleMember
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--name":
			if i+1 >= len(args) {
				fatal("--name requires a value")
			}
			name = args[i+1]
			i++
		case a == "--role":
			if i+1 >= len(args) {
				fatal("--role requires a value")
			}
			role = strings.ToLower(args[i+1])
			i++
		case strings.HasPrefix(a, "-"):
			fatal("unknown flag: %s", a)
		case email == "":
			email = a
		default:
			fatal("unexpected argument: %s", a)
		}
	}
	if email == "" {
		fatal("usage: create-user <email> [--name <text>] [--role admin|member]")
	}
	if role != auth.RoleAdmin && role != auth.RoleMember {
		fatal("role must be 'admin' or 'member'")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := store.FindOrCreateUser(ctx, "dev:"+email, email, name, role)
	if err != nil {
		fatal("create-user: %v", err)
	}
	fmt.Printf("created user %s (%s) role=%s\n", u.ID, u.Email, u.Role)
}

// cmdToken mints a gateway JWT for an existing user. Intended for testing with
// curl; JWT_SIGNING_KEY must match the running gateway's key.
func cmdToken(ctx context.Context, store *auth.Store, args []string) {
	ttl := 24 * time.Hour
	var idOrEmail string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--ttl":
			if i+1 >= len(args) {
				fatal("--ttl requires a value")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				fatal("invalid --ttl: %v", err)
			}
			ttl = d
			i++
		case strings.HasPrefix(a, "-"):
			fatal("unknown flag: %s", a)
		case idOrEmail == "":
			idOrEmail = a
		default:
			fatal("unexpected argument: %s", a)
		}
	}
	if idOrEmail == "" {
		fatal("usage: token <id-or-email> [--ttl <duration>]")
	}
	u, err := store.FindUserByIDOrEmail(ctx, idOrEmail)
	if err != nil {
		fatal("lookup: %v", err)
	}
	if u == nil {
		fatal("user not found: %s", idOrEmail)
	}
	key := []byte(os.Getenv("JWT_SIGNING_KEY"))
	if len(key) == 0 {
		fmt.Fprintln(os.Stderr, "warning: JWT_SIGNING_KEY is empty — token only works against a gateway with an empty key (DEV_MODE)")
	}
	issuer := auth.NewJWTIssuer(key, ttl)
	tok, _, err := issuer.Issue(u.ID)
	if err != nil {
		fatal("issue token: %v", err)
	}
	fmt.Println(tok)
}

func cmdDeleteUser(ctx context.Context, store *auth.Store, args []string) {
	if len(args) != 1 {
		fatal("usage: delete-user <id-or-email>")
	}
	u, err := store.FindUserByIDOrEmail(ctx, args[0])
	if err != nil {
		fatal("lookup: %v", err)
	}
	if u == nil {
		fatal("user not found: %s", args[0])
	}
	devices, tokens, err := store.DeleteUser(ctx, u.ID)
	if err != nil {
		fatal("delete: %v", err)
	}
	fmt.Printf("deleted user %s (%s); removed %d device(s) and %d refresh token(s)\n", u.ID, u.Email, devices, tokens)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
