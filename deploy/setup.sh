#!/usr/bin/env bash
# Bring up atlas-mcp on this host end-to-end: Docker Compose app, Apache
# reverse proxy + TLS for the given domain, then verify connectivity —
# local first, then this host's own view of the public hostname.
#
# Usage (run ON the target server, as root, from the repo root):
#   sudo ./deploy/setup.sh --domain atlas.example.com [--email <your-email>]
#
# Idempotent — safe to re-run (e.g. after `git pull` to pick up a code fix).
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

echo "==> 1/6  App: .env / ATLAS_TOKEN"
if [[ ! -f .env ]]; then
    TOKEN=$(openssl rand -base64 32 | tr -d '/+=')
    printf 'ATLAS_TOKEN=%s\n' "$TOKEN" > .env
    chmod 600 .env
    echo "    Generated a new ATLAS_TOKEN in .env (shown once — save it):"
    echo "    $TOKEN"
else
    echo "    .env already exists, leaving it as-is."
fi

echo "==> 2/6  App: docker compose build + up"
docker compose build
docker compose up -d
for _ in 1 2 3 4 5; do
    curl -sf -m 3 http://127.0.0.1:8787/healthz >/dev/null && break
    sleep 2
done
if ! curl -sf -m 3 http://127.0.0.1:8787/healthz >/dev/null; then
    echo "    Backend did not come up. Recent logs:" >&2
    docker compose logs --tail 30
    exit 1
fi
echo "    Backend healthy on 127.0.0.1:8787."

echo "==> 3/6  Apache: required modules"
a2enmod -q proxy proxy_http headers ssl http2 rewrite
systemctl reload apache2 2>/dev/null || true

echo "==> 4/6  TLS certificate for $DOMAIN"
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

echo "==> 5/6  Apache: full vhost (redirect + proxy + hardening)"
sed "s/__DOMAIN__/$DOMAIN/g" deploy/apache/atlas.conf.template > "/etc/apache2/sites-available/$DOMAIN.conf"
a2ensite -q "$DOMAIN"
apache2ctl configtest
systemctl reload apache2

echo "==> 6/6  Connectivity tests"
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
