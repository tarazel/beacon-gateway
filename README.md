# beacon-gateway

**The open-source gateway for [Beacon](https://tarazel.com) — the family
security app for your self-hosted [Frigate](https://frigate.video).**

Frigate gives you object detection and recording. The beacon gateway turns it
into **a family security app** — a small Go service in front of Frigate that adds
the one thing no thin Frigate client can: real multi-user. Every family member
gets their own account (Sign in with Apple or Google) and sees only the cameras you
allow, and
**nobody ever touches your Frigate login** — the gateway holds the credentials and
brokers everything. Real push, secure auth, live-view signaling, and clip playback
come with it. Frigate stays the source of truth for events, snapshots, clips, and
streams.

If you've wired Frigate up to ntfy or email for alerts, the gateway replaces
that notification layer with real push that fires even when the app is closed —
**and** adds the parts a shared Frigate login never could: real accounts,
per-user camera scope, single-use invite codes, WebRTC live-view signaling, and
clip history.

> Not affiliated with Ring or Amazon. "Ring-style" describes the experience, not
> the product.

---

## Architecture

```
Camera ──RTSP──> Frigate ──MQTT──> beacon gateway (Go) ──APNs──> iOS app
                    │                      │
                    └── snapshots/clips/streams (proxied) ──┘
                                           │
                                  HTTP (reverse proxy / tunnel / Tailscale)
```

- The **gateway** is the only surface the app talks to. It authenticates clients,
  turns Frigate MQTT events into APNs push, proxies snapshots/clips (with HTTP
  Range), and brokers WebRTC SDP with go2rtc for live view.
- The **app** never talks to Frigate directly.
- **Live view is peer-to-peer** between phone and go2rtc once SDP is exchanged;
  the gateway is only in the signaling path.

Push can be delivered two ways: directly with your **own** APNs `.p8` key
(`DirectTransport`), or forwarded to a central **push relay** that holds the key
(`RelayTransport`). The relay client is in [`internal/relayclient`](internal/relayclient);
the relay service itself is a separate component.

## What you need

- A running **Frigate** instance (with go2rtc + MQTT, as in the standard Frigate
  stack). A Coral or other detector is Frigate's concern, not the gateway's.
- A way to reach the gateway from your phone: any TLS reverse proxy, a Cloudflare
  Tunnel, or Tailscale. Cloudflare is **optional** — the gateway does its own auth.
- For push + Sign in with Apple: an **Apple Developer account** (for an APNs key,
  or to ship/sideload your own iOS client build under your own bundle ID).

## Push out of the box: the Beacon Pro relay

`RELAY_URL` defaults to Tarazel's hosted relay (`relay.tarazel.com`), so push
works with **zero setup**: your first admin sign-in registers the gateway
using that user's verified Apple/Google identity (no secret to paste), starts
a trial, and notifications just work. After the trial, keeping it active is a
small [Beacon Pro](https://tarazel.com) subscription — it entitles your whole
household, not per device, and it's the one piece of this that Tarazel hosts
rather than you.

Don't want any third party — even a privacy-minimal one — in the push path?
Set `RELAY_URL=off` and configure your own Apple `.p8` key (`APNS_*` below);
the gateway then pushes directly to APNs. That needs an Apple Developer
account, and, for push to reach the *published* apps, a rebuild under your own
bundle ID. Either way, see [Privacy](#privacy) for exactly what the relay does
and doesn't see.

## Quick start

```bash
cp .env.example .env       # then edit — see comments in that file
make build                 # builds the gateway + beacon-admin CLI
make docker                # or: docker compose up -d --build
```

No Go toolchain, or don't want to build from source? Every tagged release
publishes multi-arch (`linux/amd64` + `linux/arm64`) images to GHCR — swap
`build: .` in `docker-compose.yml` for an `image:` line and skip straight to
running it:

```yaml
image: ghcr.io/tarazel/beacon-gateway:v1.0.0   # or :latest — see Releases for tags
```

Minimum config to edit in `.env`:

- `FRIGATE_BASE_URL` — internal address is simplest (`http://frigate:5000`).
- `CAMERAS_JSON` — one entry per camera; `stream` must be the **H.264 substream**
  (see the hard rule below).
- `JWT_SIGNING_KEY` — `openssl rand -base64 48`.
- `APPLE_CLIENT_ID` — your iOS app's bundle ID (Sign in with Apple).
- `GOOGLE_CLIENT_ID` / `GOOGLE_ALLOWED_AUDIENCES` — optional; set to enable Sign in
  with Google (the Web/server OAuth client id, plus the iOS client id as an extra
  audience). Leave blank to disable Google sign-in (the endpoint returns 501).
- `APNS_*` — your `.p8` key + IDs for direct push (omit to use a relay instead).

## Users, roles, and invites

The gateway is multi-user and family-oriented:

- **The first person to sign in becomes the admin** (the instance owner). You can
  also pre-seed admins with `ADMIN_EMAILS`.
- **Admins** manage users, cameras, retention, and see every camera.
- **Members** are regular family users. By default a member sees all cameras; an
  admin can scope a member to specific cameras only.
- **Saved clips are a shared household archive**: any user with access to a
  camera can view and pin its clips; only admins change retention or force-delete.

Add a family member without guessing their Apple email: mint an **invite code**
and have them enter it on the Sign In screen. Invites are single-use and can
carry a role, camera scope, and expiry.

### `beacon-admin` CLI

```
beacon-admin list-users
beacon-admin set-role <id-or-email> <admin|member>
beacon-admin set-cameras <id-or-email> [camera ...]   # no cameras = sees all
beacon-admin invite create [--role member|admin] [--camera <id>]... [--expires 168h] [--note <text>]
beacon-admin invite list
beacon-admin invite delete <code>
beacon-admin allow <email> [--note <text>]            # legacy allowlist (invites are easier)
beacon-admin delete-user <id-or-email>
```

## iOS app

The iOS client is a separate component. Its gateway URL is **configurable** (Sign
In screen → *Gateway*, or Settings), so one build can point at any beacon
instance — point it at your gateway's public URL and sign in.

## Hard design rule: H.264 for playback, H.265 for storage only

All user-facing playback (live view, anything browser-reachable) must use the
**H.264 substream**. H.265 is for recording/archive only. iOS AVPlayer handles
HEVC, so clip playback can serve Frigate's H.265 recording — but live view and
anything a browser could reach must be H.264. `CAMERAS_JSON.stream` must point at
the H.264 substream.

## Privacy

The gateway is built so nobody but you has to see your footage or metadata:

- **Frigate stays the only place your camera data lives.** Events, snapshots,
  and clips are read from your own Frigate and proxied straight to your
  family's devices; the gateway's local cache never uploads anything upstream.
- **All PII lives in your own SQLite database** — accounts, per-camera scope,
  mute state, and notification rules never leave your instance.
- **The hosted relay is privacy-minimal by design, not just by policy.** It
  only ever sees an opaque `event_id` and device push tokens — never camera
  names, labels, or images. The real title/body/snapshot are fetched by each
  phone directly from *your* gateway (see the notification service extension /
  `internal/relayclient`), so the relay has nothing worth leaking even if it
  were compromised.
- **Run your own APNs key (`RELAY_URL=off`) and there's no third party in the
  push path at all** — `DirectTransport` talks to Apple directly.

## Status & limitations

- Off-network WebRTC live view needs a TURN server (LAN works out of the box).
- Two-way audio is not implemented.
- See [`CLAUDE.md`](CLAUDE.md) for detailed architecture and operational notes.

## License

[MIT](LICENSE).
