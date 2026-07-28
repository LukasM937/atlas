#!/usr/bin/env bash
# Encrypted off-box backup of the store. Run daily (systemd timer or cron).
# Prereq: restic init on the remote; passphrase in /etc/atlas/restic.pass (0600).
#
# STORE_DIR default (/var/lib/atlas) matches deploy/systemd/atlas.service's
# layout. Docker Compose deployments (deploy/setup.sh) bind-mount ATLAS_ROOT
# to ./data next to docker-compose.yml instead — override before running:
#   STORE_DIR=/home/pi/Documents/atlas/data ./deploy/backup.sh
set -euo pipefail
STORE_DIR="${STORE_DIR:-/var/lib/atlas}"
export RESTIC_REPOSITORY="${RESTIC_REPOSITORY:?set in /etc/atlas/backup.env}"
export RESTIC_PASSWORD_FILE=/etc/atlas/restic.pass

restic backup "$STORE_DIR" \
    --exclude "$STORE_DIR/.locks" \
    --tag atlas

restic forget --tag atlas --prune \
    --keep-daily 7 --keep-weekly 4 --keep-monthly 6

restic check --read-data-subset=5%

# Restore drill — run this by hand at least once, and after any change:
#   restic restore latest --target /tmp/restore-drill
#   diff -r "$STORE_DIR/projects" "/tmp/restore-drill$STORE_DIR/projects"
