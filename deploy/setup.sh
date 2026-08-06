#!/usr/bin/env bash
# Bring up atlas-mcp on this host end-to-end: Docker Compose app, Apache
# reverse proxy + TLS for the given domain, then verify connectivity —
# local first, then this host's own view of the public hostname.
#
# Usage (run ON the target server, as root, from the repo root):
#   sudo ./deploy/setup.sh --domain atlas.example.com [--email <your-email>]
#
# Idempotent — safe to re-run (e.g. after `git pull` to pick up a code fix).
# Rollout on re-runs is validate-then-swap, not blue-green: the new image is
# built and its own test suite run against it in an isolated throwaway
# container *before* the live container is ever touched, and the
# currently-running image is tagged ":previous" first so a bad deploy that
# still passes those checks but breaks at runtime can be rolled back with
# one command (printed when it happens, and after every tag step). Not
# zero-downtime -- `docker compose up -d` still has a brief restart gap --
# but nothing untested ever reaches the running container, and rollback
# doesn't need a rebuild. Deliberately not two live containers sharing the
# same data volume: concurrent git commits from both against the same
# working directory risk silent lock contention, and it doesn't actually
# buy extra safety over validating before the swap.
#
# Does NOT touch ufw or install fail2ban: this host may run other services
# with their own firewall rules already (it does, on the box this was
# written for) — those stay manual, reviewed steps. See the summary this
# script prints at the end for what to check by hand.
set -euo pipefail

DOMAIN=""
EMAIL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --email) EMAIL="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "Usage: $0 --domain <your-domain> [--email <your-email>]" >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "Run as root (needed for apache2ctl/certbot): sudo $0 --domain $DOMAIN" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> 1/8  App: .env / ATLAS_TOKEN"
if [[ ! -f .env ]]; then
    TOKEN=$(openssl rand -base64 32 | tr -d '/+=')
    printf 'ATLAS_TOKEN=%s\n' "$TOKEN" > .env
    chmod 600 .env
    echo "    Generated a new ATLAS_TOKEN in .env (shown once — save it):"
    echo "    $TOKEN"
else
    echo "    .env already exists, leaving it as-is."
fi

echo "==> 2/8  App: tag currently-running image as a rollback anchor"
IMAGE_NAME="$(docker compose config --images atlas 2>/dev/null | head -1)"
RUNNING_ID="$(docker compose ps -q atlas 2>/dev/null)"
if [[ -n "$RUNNING_ID" && -n "$IMAGE_NAME" ]]; then
    CURRENT_IMAGE="$(docker inspect --format='{{.Image}}' "$RUNNING_ID" 2>/dev/null || true)"
    if [[ -n "$CURRENT_IMAGE" ]]; then
        docker tag "$CURRENT_IMAGE" "${IMAGE_NAME}:previous"
        echo "    Tagged as ${IMAGE_NAME}:previous. Roll back with:"
        echo "      docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest && docker compose up -d --force-recreate"
    fi
else
    echo "    Nothing running yet — first deploy, no rollback anchor needed."
fi

echo "==> 3/8  App: build + validate before touching the live container"
docker compose build
echo "    Checking the new image actually imports cleanly..."
if ! docker compose run --rm atlas python -c "import atlas_mcp.app" 2>&1; then
    echo "    New image failed to import atlas_mcp.app -- not touching the running container." >&2
    echo "    (The old container, if any, is still up and unaffected.)" >&2
    exit 1
fi
echo "    Running the store test suite against the new image..."
if ! docker compose run --rm atlas python tests/test_store.py; then
    echo "    New image failed its own test suite -- not touching the running container." >&2
    echo "    (The old container, if any, is still up and unaffected.)" >&2
    exit 1
fi
echo "    New image imports cleanly and passes its tests. Proceeding with the swap."

echo "==> 4/8  App: swap to the new image"
docker compose up -d
for _ in 1 2 3 4 5; do
    curl -sf -m 3 http://127.0.0.1:8787/healthz >/dev/null && break
    sleep 2
done
if ! curl -sf -m 3 http://127.0.0.1:8787/healthz >/dev/null; then
    echo "    Backend did not come up after the swap. Recent logs:" >&2
    docker compose logs --tail 30
    if [[ -n "${IMAGE_NAME:-}" ]] && docker image inspect "${IMAGE_NAME}:previous" >/dev/null 2>&1; then
        echo "    Rolling back to the previous image automatically." >&2
        docker tag "${IMAGE_NAME}:previous" "${IMAGE_NAME}:latest"
        docker compose up -d --force-recreate
    fi
    exit 1
fi
echo "    Backend healthy on 127.0.0.1:8787."

echo "==> 5/8  Apache: required modules"
a2enmod -q proxy proxy_http headers ssl http2 rewrite
systemctl reload apache2 2>/dev/null || true

echo "==> 6/8  TLS certificate for $DOMAIN"
CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
if [[ ! -f "$CERT" ]]; then
    echo "    No existing cert — bootstrapping one via HTTP-01."
    echo "    This needs $DOMAIN's DNS pointed here and port 80 reachable"
    echo "    from the internet for the challenge."
    cat > "/etc/apache2/sites-available/$DOMAIN.conf" <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
</VirtualHost>
EOF
    a2ensite -q "$DOMAIN"
    apache2ctl configtest
    systemctl reload apache2
    CERTBOT_ARGS=(certonly --apache -d "$DOMAIN" --non-interactive --agree-tos)
    if [[ -n "$EMAIL" ]]; then
        CERTBOT_ARGS+=(--email "$EMAIL")
    else
        CERTBOT_ARGS+=(--register-unsafely-without-email)
    fi
    certbot "${CERTBOT_ARGS[@]}"
else
    echo "    Existing cert found at $CERT, reusing it."
fi

echo "==> 7/8  Apache: full vhost (redirect + proxy + hardening)"
sed "s/__DOMAIN__/$DOMAIN/g" deploy/apache/atlas.conf.template > "/etc/apache2/sites-available/$DOMAIN.conf"
a2ensite -q "$DOMAIN"
apache2ctl configtest
systemctl reload apache2

echo "==> 8/8  Connectivity tests"
echo "    -- local, direct to backend --"
curl -s -o /dev/null -w "    http://127.0.0.1:8787/healthz -> %{http_code}\n" http://127.0.0.1:8787/healthz

echo "    -- local, through Apache (correct SNI via --resolve) --"
curl -s --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null \
    -w "    https://$DOMAIN/healthz -> %{http_code}  (expect 200 here, 403 from elsewhere — that's correct, healthz is localhost-only)\n" \
    "https://$DOMAIN/healthz"
curl -s --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null \
    -w "    https://$DOMAIN/openapi.json -> %{http_code}  (expect 200)\n" \
    "https://$DOMAIN/openapi.json"

echo "    -- outgoing: this host's own view of the public hostname --"
if ! curl -s -m 6 -o /dev/null -w "    https://$DOMAIN/openapi.json -> %{http_code}\n" "https://$DOMAIN/openapi.json"; then
    echo "    (no response — could be DNS not pointed here yet, port 80/443"
    echo "     not forwarded, or this router doesn't support NAT hairpin/"
    echo "     loopback. The last one is common and does NOT mean external"
    echo "     clients can't reach it.)"
fi
echo "    This test is necessary but not sufficient if this host and the"
echo "    machine you're reading this from share a network path — confirm"
echo "    once more from a genuinely separate network (e.g. phone on"
echo "    cellular data) before trusting it fully."

echo
echo "Done. Not touched by this script, check by hand:"
echo "  - ufw: confirm 80/443 are allowed (ufw status) — this host may run"
echo "    other services with their own rules already."
echo "  - fail2ban: optional, see deploy/fail2ban/ and TODO.md phase 3.5."
