# Contributing to beacon-gateway

## Build & test

```bash
make build              # gateway + beacon-admin CLI
make test                # go test ./...
go vet ./...
```

`DEV_MODE=true` in `.env` bypasses `JWT_SIGNING_KEY`/`APPLE_CLIENT_ID` validation
so you can run the gateway locally without a full Apple/Frigate setup. See
`.env.example` for every config option.

CI (`.github/workflows/ci.yml`) runs `go vet`, `go test ./...`, and `make build`
on every push and PR to `main` — make sure all three pass before opening a PR.

## The one hard rule

**H.265 stays in storage only. All user-facing playback uses the H.264
substream.** Live view (WebRTC/HLS) and anything browser-reachable must never
serve the H.265 main stream — only clip playback (native AVPlayer/ExoPlayer) may
use H.265. If a change seems to need the main stream for user-facing display,
flag it in the PR description rather than silently wiring it up. See
[`CLAUDE.md`](CLAUDE.md) for the full architecture writeup and the reasoning
behind this constraint.

## Opening issues & PRs

- Bug reports and feature requests: open a GitHub issue.
- PRs: keep them focused — one change per PR is easier to review than a bundle.
  Reference the issue it closes, if any.
- No CLA required. By submitting a PR you agree it's licensed under this repo's
  [MIT license](LICENSE).
