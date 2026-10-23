#!/usr/bin/env bash
# Soken contract-review backup (plan-v4 09 O3): the Postgres database and the report store,
# one dated archive each, rotated by age. Runs from soken-backup.timer on the host.
#
#   SOKEN_PG_CONTAINER   docker container that runs Postgres (default soken-audit-test-pg)
#   SOKEN_PG_USER/DB     database user and name (default soken/soken)
#   SOKEN_REPORT_STORE   report objects root (default <public-export>/.sbx/reports)
#   SOKEN_BACKUP_DIR     destination (default /var/backups/soken), SOKEN_BACKUP_KEEP_DAYS (default 14)
set -euo pipefail
umask 077
container="${SOKEN_PG_CONTAINER:-soken-audit-test-pg}"
user="${SOKEN_PG_USER:-soken}"
db="${SOKEN_PG_DB:-soken}"
store="${SOKEN_REPORT_STORE:-/opt/soken-audit-test/public-export/.sbx/reports}"
dest="${SOKEN_BACKUP_DIR:-/var/backups/soken}"
keep="${SOKEN_BACKUP_KEEP_DAYS:-14}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$dest"
tmp="$(mktemp -d "$dest/.tmp.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

docker exec "$container" pg_dump -U "$user" -d "$db" --no-owner --format=custom > "$tmp/db.dump"
gzip -9 "$tmp/db.dump"
mv "$tmp/db.dump.gz" "$dest/db-$stamp.dump.gz"

if [ -d "$store" ]; then
  tar -C "$(dirname "$store")" -czf "$tmp/reports.tgz" "$(basename "$store")"
  mv "$tmp/reports.tgz" "$dest/reports-$stamp.tgz"
fi

find "$dest" -maxdepth 1 -type f \( -name 'db-*.dump.gz' -o -name 'reports-*.tgz' \) -mtime +"$keep" -delete
ls -la "$dest" | tail -n +2 | awk '{print $5, $9}' | sort -k2 | tail -4
