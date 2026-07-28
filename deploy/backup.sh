#!/usr/bin/env bash
# Encrypted off-box backup of the store. Run from a systemd timer, daily.
# Prereq: restic init on the remote; passphrase in /etc/atlas/restic.pass (0600).
set -euo pipefail
export RESTIC_REPOSITORY="${RESTIC_REPOSITORY:?set in /etc/atlas/backup.env}"
export RESTIC_PASSWORD_FILE=/etc/atlas/restic.pass

restic backup /var/lib/atlas \
    --exclude '/var/lib/atlas/.locks' \
    --tag atlas

restic forget --tag atlas --prune \
    --keep-daily 7 --keep-weekly 4 --keep-monthly 6

restic check --read-data-subset=5%

# Restore drill — run this by hand at least once, and after any change:
#   restic restore latest --target /tmp/restore-drill
#   diff -r /var/lib/atlas/projects /tmp/restore-drill/var/lib/atlas/projects
