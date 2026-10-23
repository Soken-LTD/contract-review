# Host operations (plan-v4 part 09 O1, O3, O5)

Reference units for the stand (`/opt/soken-audit-test/public-export`). Install with
`cp scripts/ops/soken-*.{service,timer} /etc/systemd/system/ && systemctl daemon-reload &&
systemctl enable --now soken-retention.timer soken-backup.timer`.

- `soken-retention.timer`: hourly `python -m soken_review.worker.retention` (rules in that module's
  docstring: failed and refused jobs 7 days, ready idle 24 h, reports at `expires_at`, build cache,
  orphan directories). `--dry-run --json` prints what a pass would do.
- `soken-backup.timer`: daily `backup.sh`: `pg_dump` (custom format, gzip) through the Postgres
  container plus a tarball of the report store, rotated after 14 days under `/var/backups/soken`.
  Restore: `gunzip -c db-<stamp>.dump.gz | docker exec -i <pg> pg_restore -U soken -d soken --clean`.
- `GET /healthz` on the API: 200 when the database answers and a worker heartbeat is at most 90 s
  old, else 503 with `{"db": ..., "worker_age_s": ...}`. Point the uptime monitor at it.
