#!/usr/bin/env bash
# Multi-user authorization smoke test for the beacon gateway.
#
# Verifies roles + per-camera scope + invites WITHOUT needing any Apple IDs, by
# seeding users and minting JWTs with beacon-admin. Touches nothing in a real
# deployment: it uses a throwaway DB in a temp dir and a local gateway on :8099.
#
# Usage:  bash scripts/test-multiuser.sh
# Requires: go (to build), curl.
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

ADMIN=/tmp/beacon-admin
GW=/tmp/beacon-gateway
go build -o "$ADMIN" ./cmd/admin
go build -o "$GW" ./cmd/gateway

DBT="$(mktemp -d)/beacon-test.db"
export JWT_SIGNING_KEY="test-signing-key-32-bytes-minimum-padding-xxxx"

echo "## seeding users (alice=admin, bob=member scoped to deimos)"
"$ADMIN" --db "$DBT" create-user alice@test --name Alice --role admin
"$ADMIN" --db "$DBT" create-user bob@test   --name Bob   --role member
"$ADMIN" --db "$DBT" set-cameras bob@test deimos
"$ADMIN" --db "$DBT" list-users

echo "## starting local gateway on :8099 (DEV_MODE, 2 cameras, no Frigate needed)"
DEV_MODE=true HTTP_ADDR=:8099 PUBLIC_BASE_URL=http://localhost:8099 DB_PATH="$DBT" \
CAMERAS_JSON='[{"id":"deimos","display_name":"Deimos","stream":"deimos_sub"},{"id":"garage","display_name":"Garage","stream":"garage_sub"}]' \
"$GW" >/tmp/beacon-gw.log 2>&1 &
GWPID=$!
trap 'kill $GWPID 2>/dev/null || true' EXIT
for _ in $(seq 1 25); do curl -s localhost:8099/healthz >/dev/null 2>&1 && break; sleep 0.2; done

ATOKEN=$("$ADMIN" --db "$DBT" token alice@test)
BTOKEN=$("$ADMIN" --db "$DBT" token bob@test)
A=(-s -H "Authorization: Bearer $ATOKEN")
B=(-s -H "Authorization: Bearer $BTOKEN")

echo; echo "## /api/me";            curl "${A[@]}" localhost:8099/api/me; echo; curl "${B[@]}" localhost:8099/api/me; echo
echo; echo "## /api/cameras";       curl "${A[@]}" localhost:8099/api/cameras; echo; curl "${B[@]}" localhost:8099/api/cameras; echo
echo; echo "## bob deimos/garage";  curl "${B[@]}" -o /dev/null -w "deimos=%{http_code} " localhost:8099/api/cameras/deimos/live
                                    curl "${B[@]}" -o /dev/null -w "garage=%{http_code}\n" localhost:8099/api/cameras/garage/live
echo; echo "## invites (admin-only)"
curl "${B[@]}" -o /dev/null -w "bob POST=%{http_code}\n" -X POST -H 'Content-Type: application/json' -d '{"role":"member"}' localhost:8099/api/invites
curl "${A[@]}" -X POST -H 'Content-Type: application/json' -d '{"role":"member","cameras":["garage"],"note":"sister"}' localhost:8099/api/invites; echo
echo "(done)"
