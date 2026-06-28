# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Added admin session management endpoints:
  - `POST /admin/sessions/:sid/revoke` — mark a session as administratively revoked (durable `revokedAt`).
  - `GET /admin/sessions` — paginated listing of sessions with `activeOnly` filter and pagination (`limit`/`offset`).
- Session-manager: durable revocation semantics — `validateSession` now rejects tokens tied to sessions with `revokedAt` set in the DB.
- Tests: added unit and integration tests for admin revoke/list and session-manager behaviors.
- Notes: Admin revocation is best-effort; if DB updates fail the system will remove ephemeral state to avoid leaving a live session behind.
