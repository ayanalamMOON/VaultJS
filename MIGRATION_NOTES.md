# Migration notes — sessions columns

This document describes the recommended steps to deploy the sessions column migration safely.

Overview
- We added two new columns to the `sessions` table: `uid TEXT` and `revokedAt INTEGER`.
- These columns are indexed (`idx_sessions_uid`, `idx_sessions_revokedAt`) so admin listing/count operations can run efficiently on large tables.

Deployment order (recommended)
1. Push code that contains the schema ALTERs, the migration scripts, and the updated application logic (this change set).
2. Run a pre-migration backup dump (SQL/text) locally or in your staging environment:

   npm run dump:sessions

   This writes `infra/db/session-backups/sessions-sql-backup-<timestamp>.sql` containing `INSERT` statements for restoring the sessions table if required.

3. Run the JSON backup + migration script which will:
   - write a JSON snapshot of the sessions table to `infra/db/session-backups/sessions-backup-<timestamp>.json` and
   - populate the `uid` and `revokedAt` columns from the payload JSON values for existing rows.

   npm run migrate:sessions

4. Verify the migration:
   - Check the backup files in `infra/db/session-backups/`
   - Run a quick query via sqlite CLI or a small script to verify `uid` and `revokedAt` are populated for recent sessions.
   - Run the test-suite (recommended): `npm test -- --runInBand`

5. Switch traffic to the updated code (restart or roll new instances). Because the application expects the new columns, this order ensures no downtime or inconsistent behavior.

Rollback
- If you need to rollback the DB changes, you can restore the sessions table using the SQL file produced by `dump:sessions` (sqlite3 CLI or programmatic restore).

Restore using the provided script
- We include a helper to replay the SQL backup into the DB. By default it picks the most recent `sessions-sql-backup-*.sql` file, or you can provide a path via the `BACKUP_PATH` environment variable.

   # restore latest backup
   npm run restore:sessions

   # or restore a specific file
   BACKUP_PATH=infra/db/session-backups/sessions-sql-backup-2026-05-27T14-24-12-380Z.sql npm run restore:sessions

Notes
- The restore script executes statements one-by-one and will continue on individual statement failure while logging warnings — this is safer for best-effort rollbacks where some rows may conflict. For a strict restore prefer using the sqlite CLI to drop & recreate the sessions table before replaying the SQL backup.


Notes
- The migration scripts are idempotent; re-running them will not repeatedly modify rows.
- Consider taking an extra offline DB snapshot (file copy of `infra/db/vault.db`) before making changes in production.
