# beacon-gateway

The open-source Go gateway for beacon — a self-hosted, Ring-style home security
backend that sits in front of [Frigate](https://frigate.video) and serves a
native iOS client. This repo is the **gateway service + admin CLI** only. The
iOS app and the central push relay are separate repos.

---

## Hard design rule

**H.265 stays in storage only. All user-facing playback uses the H.264 substream.**

This is a load-bearing constraint, not a preference. Frigate's main stream is
H.265 (recording/archive); the substream is H.264 (detection + all user-facing
playback). iOS AVPlayer handles HEVC, so clip playback can serve Frigate's H.265
recording — but **live view (WebRTC) and anything browser-reachable must be
H.264.** If a feature seems to need the main stream for user-facing display,
**flag it** rather than silently using H.265.

---

## Architecture

```
Camera ──RTSP──> Frigate ──MQTT──> Gateway (Go) ──APNs──> iOS app
                                       │
                              HTTP via reverse proxy / tunnel / Tailscale
```

- The **gateway** is the only public surface the app talks to. It authenticates
  Sign in with Apple + JWT, translates MQTT events into APNs push, proxies
  Frigate snapshots/clips, and brokers WebRTC SDP with go2rtc.
- The **app** never touches Frigate directly.
- **Live view is peer-to-peer** (WebRTC) between the device and go2rtc once SDP is
  exchanged; the gateway is only in the signaling path — it doesn't relay video.
  WebRTC needs UDP, so it only works on-LAN through an HTTP tunnel. **Off-network
  the app falls back to HLS**, which the gateway *does* proxy (`/api/cameras/{id}/
  hls/*`): it fetches go2rtc's HLS (H.264 substream — the hard rule holds), rewrites
  every playlist URI to route segments back through the authed gateway, and streams
  them. Segment URLs are SameOrigin-checked before fetch (they arrive in a client
  param — else SSRF). The app tries WebRTC first and auto-falls-back to HLS on
  failure (plus a manual toggle).

---

## Repo layout

```
cmd/
├── gateway/        long-running daemon
└── admin/          beacon-admin CLI (allowlist + user management)
internal/
├── api/            HTTP handlers + router (stdlib net/http, Go 1.22+ routing)
├── auth/           Sign in with Apple verification, JWT, refresh tokens, allowlist
├── apns/           APNs delivery: Sender + Transport (Direct .p8 / Relay)
├── camhealth/      polls Frigate /api/stats → per-camera offline state (debounced)
├── cameras/        in-memory registry: id → display_name + go2rtc stream name
├── clips/          background clip-cache pruner (retention)
├── config/         env-driven config
├── db/             sqlite (modernc.org/sqlite, pure Go) + embedded migrations
├── events/         Frigate event store + push trigger logic
├── frigate/        HTTP client for Frigate (snapshot/clip proxy with Range)
├── go2rtc/         WHEP (WebRTC SDP exchange) client
├── mqtt/           Frigate event subscriber (eclipse/paho.mqtt.golang)
├── relayclient/    wire-contract types for the push relay (KEEP IN SYNC w/ relay repo)
└── settings/       key/value settings store
Dockerfile          distroless static-debian12, nonroot user
docker-compose.yml  deployment compose
Makefile            build / test / docker targets
.env.example        all configurable env vars with comments
```

---

## Endpoints (current surface)

```
GET    /healthz

POST   /api/auth/apple                 # Sign in with Apple — token → JWT + refresh
POST   /api/auth/apple/callback        # Apple web-flow (Android SIWA) form_post → 302 beacon-auth://callback
POST   /api/auth/google                # Sign in with Google — id_token → JWT + refresh (501 if GOOGLE_CLIENT_ID unset)
POST   /api/auth/refresh               # refresh token → new JWT + refresh

POST   /api/devices                    # register push device token { apns_token, platform?, app_version? } — platform "ios"(default)|"android"
GET    /api/me                         # { user_id, email, name, role, is_admin, all_cameras, cameras[] }
GET    /api/mute                       # { muted_until, cameras:[{camera,muted_until}] }
POST   /api/mute                       # { duration_seconds, camera? } — camera omitted = global; 0 clears
DELETE /api/mute                       # clears the global mute
GET    /api/settings/clips             # { retention_days }
PUT    /api/settings/clips             # { retention_days } (clamped 1..3650) — ADMIN ONLY
GET    /api/notification-rules         # caller's own rules { labels[], zones[], min_score, cooldown_seconds, quiet_start_min, quiet_end_min }
PUT    /api/notification-rules         # replace caller's rules (server normalizes/clamps; echoes result)
GET    /api/cameras/{id}/live          # descriptor { protocol, webrtc_url, hls_url } — hls_url embeds a short-lived HLS token
GET    /api/cameras/{id}/hls/index.m3u8  # HLS playlist proxy (H.264 substream via go2rtc); token via ?token= or Bearer
GET    /api/cameras/{id}/hls/r         # HLS segment/sub-playlist proxy (?u=<b64 go2rtc URL>&token=)

POST   /api/checkout                   # ADMIN: { plan? } → { url } — Stripe Checkout via relay (relay mode only)
GET    /api/subscription               # { managed, plan, sub_status, active, expires_at } — household Beacon Pro status

POST   /api/invites                    # ADMIN: { role?, cameras?[], note?, expires_in_seconds? } → invite + code
GET    /api/invites                    # ADMIN: list invites
DELETE /api/invites/{code}             # ADMIN: revoke an invite
GET    /api/events                     # ?camera=&label=&since=&limit= (scoped to caller's cameras)
GET    /api/events/search              # ?query=&limit= — semantic (NL) search via Frigate CLIP embeddings; scope-filtered, relevance-ordered; 501 if Frigate semantic_search disabled
GET    /api/events/{id}
GET    /api/events/{id}/push           # { title, body, thread_id, has_snapshot } — MEDIA-scoped; NSE reads this to render a minimal relay push
GET    /api/events/{id}/snapshot       # proxied JPEG with Range support
GET    /api/events/{id}/clip           # proxied MP4 with Range support
HEAD   /api/events/{id}/clip           # AVPlayer probes this before downloading
PUT    /api/events/{id}/keep           # { keep } — pin/unpin clip from cache cleanup

GET    /api/cameras                    # [{ id, display_name, offline }] — `offline` = no frames for CAMERA_OFFLINE_AFTER
GET    /api/cameras/{id}/snapshot      # latest detect-frame JPEG (H.264 substream); ?h= scales
GET    /api/cameras/{id}/live          # connection descriptor: { id, display_name, protocol, webrtc_url, offline }
POST   /api/cameras/{id}/webrtc        # body: SDP offer (application/sdp), response: SDP answer
```

All `/api/*` routes except auth require `Authorization: Bearer <jwt>`.

---

## Roles & per-camera scope

Every user has a `role`: `admin` or `member` (`users.role`, default `member`).
- **First user to sign in is auto-promoted to admin**; emails in `ADMIN_EMAILS`
  are also promoted. Change later with `beacon-admin set-role`.
- **Admins** see all cameras and reach admin-only routes (`AdminOnly` middleware,
  which re-checks role from the DB each request).
- **Per-camera scope** (`user_cameras` table): an admin or a member with *zero*
  rows sees all cameras; a member with rows sees exactly those. Helper:
  `auth.Store.AccessibleCameras(ctx, userID) (cams, all, err)`. Enforced in
  `ListCameras`, the camera-id endpoints (`ensureCameraAccess`), `ListEvents`
  (`ListFilter.Cameras`), the per-event endpoints (`eventForUser`), and the push
  dispatcher SQL (`SendToAll` only pushes to users who can access the camera).
- **Clips are a shared household archive**: any user with camera access can view
  and pin (`keep_clip`); retention + force-delete are admin-only.

---

## Auth model

Three boundaries:
1. **App → gateway:** the app sends a **provider ID token** (Apple *or* Google) →
   gateway issues its own HS256 JWT
   (15 min) + opaque refresh token (90 days, sha256-hashed in DB). Refresh tokens
   are single-use; consuming one revokes it and issues a new pair. Sign-in and
   refresh **also issue a `media_token`**: a long-lived (`MEDIA_TOKEN_TTL`, default
   30 days), media-scoped HS256 JWT (`scope: "media"`). It exists because the iOS
   notification service extension can't refresh the 15-min access token, so a stale
   token made snapshot fetches 401. `auth.Middleware` (general endpoints) **rejects**
   media-scoped tokens; `auth.MediaMiddleware` (snapshot/clip routes only) accepts
   access *or* media. The media token still carries the user's `sub`, so per-camera
   scope is enforced.
   - **Providers:** `AppleVerifier` and `GoogleVerifier` each validate the provider's
     RS256 JWKS-signed token against a **set** of accepted audiences
     (`APPLE_CLIENT_ID`∪`APPLE_ALLOWED_AUDIENCES`; `GOOGLE_CLIENT_ID`∪
     `GOOGLE_ALLOWED_AUDIENCES`). Google is disabled (501) when `GOOGLE_CLIENT_ID` is
     empty. Both handlers converge on `completeProviderSignIn`.
   - **Identity + linking:** `user_identities (provider, provider_sub) → user` is the
     authoritative map (migration `0009`; existing Apple users backfilled). Sign-in
     resolves in order: (1) known identity → that user; (2) a *verified* email
     matching an existing user → link this identity to them (cross-provider merge);
     (3) new user, gated by allowlist/invite. Only step 3 is gated. `users.apple_sub`
     is a legacy NOT NULL/UNIQUE anchor only (`google:<sub>` synthesized for
     Google-only users).
2. **Gateway → Frigate:** Optional Cloudflare Access service token (machine-to-
   machine). Set `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` to inject
   `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers on every Frigate
   request. Omit if Frigate is reached internally without Access.
3. **Gateway → APNs:** Token-based auth using a `.p8` key (NOT cert-based) —
   either directly (`DirectTransport`) or via the relay (`RelayTransport`, which
   holds the key instead).

## Allowlist & invites

A new sign-in (Apple *or* Google) is admitted if **either** the email is allowlisted
**or** a valid invite code is presented (`invite_code` in the sign-in body). A
returning user, or one linked to an existing account by verified email, is not
re-gated.

Allowlist — two sources, unioned: the `APPLE_ALLOWED_EMAILS` env var (bootstrap)
and the `allowed_emails` SQLite table (managed via `beacon-admin`). Invites
(`invites` table) are the easier path: an admin mints a single-use code carrying
a role + optional camera scope + expiry; the invitee enters it on the Sign In
screen; redemption creates their account and consumes the code (single-use,
enforced via a conditional UPDATE). Codes use an unambiguous alphabet, `XXXX-XXXX`.

---

## Event & push flow

1. Frigate publishes to MQTT `frigate/events` with `type` (`new`/`update`/`end`)
   and the event state.
2. Gateway upserts every phase into the `events` table.
3. On the `new` phase only, the gateway selects devices (honoring mute + per-camera
   scope — all PII/selection logic lives here), then applies **per-user notification
   rules** (`internal/notifrules`) via the `apns.Ruler` seam: for each eligible
   user, their stored rule (label allowlist / zone / min-score / quiet-hours /
   per-camera cooldown) decides whether to notify them. Users filtered out here
   never reach the relay/APNs (saves push volume + honors each member's prefs).
   Rules default to allow-all, evaluate in the gateway's local time, and fail open
   on a storage error. Surviving tokens are then **bucketed by device platform**
   (`ios`/`android`) and delivered per-platform, so each routes to the right push
   backend (`Transport.Deliver` takes the platform; the relay routes ios→APNs,
   android→FCM). Delivery goes via the configured `apns.Transport`, which also
   **renders its own payload**
   (`Transport.BuildPayload`), because the two paths have different privacy needs:
   - `DirectTransport` — signs with the gateway's own `.p8` and POSTs to APNs.
     Builds the **rich payload** (title/body/camera/label/snapshot_url); no third
     party sees it, so the NSE just attaches the snapshot image.
   - `RelayTransport` — forwards `{device_tokens, payload}` to the relay's
     `/v1/push`; the relay holds the `.p8` and signs. Builds a **privacy-minimal
     payload** — `mutable-content` + `event_id` + a generic placeholder alert, and
     nothing else. The relay therefore never sees camera/label/snapshot; the
     on-device NSE fetches those from the user's own gateway via
     `GET /api/events/{id}/push` (+ `/snapshot`), authed with its media token.
     Registration is **account-based**: `RELAY_URL` defaults to the hosted relay, and
     on the owner's first admin sign-in the gateway forwards that admin's verified
     Apple/Google **ID token** to `/v1/register` (no shared secret); the relay verifies
     it and binds the instance to that identity. The returned instance token is
     persisted in `settings` (`relay_instance_token`) and read **lazily on each push**
     (the transport holds a `tokenFn`, not a static token, since registration happens
     after startup). `RELAY_URL=off` disables the relay (direct mode);
     `RELAY_REGISTRATION_SECRET` is a legacy fallback.

On the `end` phase (clip now available), the dispatcher **pre-warms the clip
cache** in the background (`prewarmClip` → `frigate.EnsureCachedClip`) so a later
notification-tap skips the synchronous download+remux. Concurrent cachers of the
same event id are serialized by a per-id lock in `frigate.Client` (a pre-warm
racing a user tap can't run ffmpeg twice on the same temp files).

The relay never sees user data — only a device token + an opaque, content-free
payload. The contract types live in `internal/relayclient` and **must be kept in
sync** with the relay repo's `internal/relay` definitions.

**Lapsed subscription is loud, not silent.** When the relay rejects a push with
HTTP 402 (the instance's Beacon Pro subscription lapsed / trial expired),
`RelayTransport.Deliver` returns the `apns.ErrSubscriptionInactive` sentinel and
`Sender.SendToAll` logs a prominent `PUSH DROPPED …` WARN (with the dropped-device
count) instead of an opaque delivery error. The app surfaces the same state via
`GET /api/subscription` (`active:false`) as an app-wide banner, so a family whose
push has stopped is never left guessing.

---

## Storage

SQLite with WAL mode, single file (`data/beacon.db`). Tables: `users` (incl.
global `muted_until` + `role`), `devices`, `events` (incl. `keep_clip`),
`refresh_tokens`, `allowed_emails`, `camera_mutes`, `user_cameras`, `invites`,
`settings` (key/value), `notification_rules` + `notification_cooldowns` (per-user
push rules + cooldown state), plus `schema_migrations` tracking applied migrations
from `internal/db/migrations/*.sql`.

---

## Build / test / run

```bash
make build       # gateway + admin CLI
make test        # all Go tests
make docker      # docker-compose build
go vet ./...
```

Tests cover: allowlist roundtrip, DeleteUser CASCADE, refresh-token revocation,
role + camera-scope (`AccessibleCameras`), invite lifecycle, Frigate Proxy Range +
CF Access header forwarding + HEAD passthrough, CameraLive descriptor shape,
ListCameras scope filtering, scoped-member 403, and the gateway↔relay transport
contract (against a stub relay in `internal/apns/transport_test.go`).

---

## Configuration

All config is env-driven; reference `.env.example`.

Required for production:
- `JWT_SIGNING_KEY` — 32+ bytes, `openssl rand -base64 48`.
- `APPLE_CLIENT_ID` — must match the iOS app bundle ID.
- `CAMERAS_JSON` — JSON array, one entry per camera:
  `[{"id":"front_door","display_name":"Front Door","stream":"front_door_sub"}]`.
  `stream` must be the **H.264 substream** name in go2rtc.
- Push (default): the hosted **relay** — `RELAY_URL` defaults to it and the gateway
  self-registers on the owner's first sign-in, so no push config is needed. Set
  `RELAY_URL=off` for **direct** mode, which then needs `APNS_KEY_PATH` + `APNS_KEY_ID`
  + `APNS_TEAM_ID` + `APNS_BUNDLE_ID`.
- Optional: `CF_ACCESS_CLIENT_ID` / `_SECRET` for Frigate behind Cloudflare Access.
- Optional (camera-offline detection, `internal/camhealth`): `CAMERA_HEALTH_POLL_INTERVAL`
  (default `30s`) and `CAMERA_OFFLINE_AFTER` (default `120s`, matches Frigate's own
  no-segments watchdog). The monitor polls Frigate `/api/stats` for each camera's
  `camera_fps` and flags a camera `offline` once it's had no frames for
  `CAMERA_OFFLINE_AFTER` (asymmetric debounce: flips online again on the first good
  frame, so a flapping camera doesn't thrash the tag). It drives the `offline` field
  on the camera API **only** — it never triggers a push.

Set `DEV_MODE=true` to bypass `JWT_SIGNING_KEY` / `APPLE_CLIENT_ID` validation for
local development. APNs is skipped automatically when not configured.

---

## Known footguns

- **`internal/relayclient` is a hand-copied subset of the relay's contract** — if
  the relay's `PushRequest`/`PushResponse`/`RegisterResponse` change, update both.
- **`@MainActor`-style cross-process gotchas live in the iOS repo**, not here.
- **APNs sandbox vs production:** `APNS_USE_SANDBOX=true` for TestFlight/debug,
  `false` for App Store. The push topic (`APNS_BUNDLE_ID`) is the **app** bundle
  ID, not the extension's.
- **Refresh handler / token rotation:** refresh tokens are single-use but have a
  90-day lifetime; no reuse-after-rotation auto-revoke yet.

---

## Where to look first

- New endpoint: `internal/api/handlers.go`, `internal/api/router.go`.
- Database schema: `internal/db/migrations/*.sql`.
- HTTP wire format: `internal/api/handlers.go` — must agree with the iOS repo's
  `API/Models.swift`. All event JSON is snake_case.
- Push transport selection + relay seam: `internal/apns/`.
