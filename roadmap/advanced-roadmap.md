# VaultJS Advanced Roadmap

This roadmap captures the next integration phases for VaultJS after the core security hardening, SIEM export pipeline, and containment workflows already implemented in the repository.

## Current Baseline

VaultJS currently includes:

- policy change history persistence
- immutable SIEM export job snapshots with batch IDs
- signed manifest generation and verification
- automatic containment for failed verification / replay protection checks
- persisted containment evidence bundles
- admin endpoints for export, verification, containment, and policy control
- expanded integration and unit coverage
- operator guidance for key rotation and incident response

## Roadmap Goals

1. Make containment fully lifecycle-managed, not just pause-on-fail.
2. Improve export and replay observability for security operations.
3. Add stronger recovery, retention, and audit workflows.
4. Extend the control plane so operators can resolve incidents without manual database intervention.

## Phase 1 — Containment Lifecycle Hardening

### Objectives

- Add explicit resume and resolve actions for contained batches.
- Track containment state transitions as first-class audit events.
- Support acknowledgement, assignment, and closure metadata.
- Make paused batches visible in the admin API and export metadata.

### Planned features

- `POST /admin/audit/export/jobs/:batchId/containment/resolve`
- `POST /admin/audit/export/jobs/:batchId/containment/resume`
- `POST /admin/audit/export/jobs/:batchId/containment/acknowledge`
- containment status transitions: `paused -> acknowledged -> resolved`
- append-only containment history records

### Success criteria

- Operators can pause, inspect, acknowledge, and resolve a batch without touching SQLite directly.
- Every state transition is audit logged.
- Repeated verification failures do not duplicate containment bundles for the same batch.

## Phase 2 — Export Replay Observability

### Objectives

- Expose replay-chain health in a compact operator-friendly format.
- Provide a queryable history of manifest hashes and verification results.
- Make SIEM export events easier to correlate with incident timelines.

### Planned features

- `/admin/audit/export/jobs/:batchId/health`
- `/admin/audit/export/replay-chains`
- export timeline view grouped by batch ID
- manifest lineage summaries
- failure reason distribution reporting

### Success criteria

- Operators can see whether a batch failed due to hash mismatch, signature mismatch, or chain break.
- Replay issues are traceable across manifest generations.
- Health checks can be automated from CI or scheduled jobs.

## Phase 3 — Retention and Recovery Controls

### Objectives

- Add retention policies for old exports, manifests, and containment evidence.
- Support safe archival of frozen evidence bundles.
- Allow explicit export regeneration from retained audit events.

### Planned features

- retention policy settings for export manifests and containment files
- archival directory support with checksum validation
- export regeneration from event history for approved operators
- controlled purge workflow with safety confirmation

### Success criteria

- Old evidence can be retained or archived based on policy instead of remaining forever in the active folder.
- Regenerated exports remain cryptographically traceable to the original audit record set.
- No purge action removes evidence without a recorded approval trail.

## Phase 4 — Operator Workflow Automation

### Objectives

- Reduce manual steps during incident handling.
- Improve consistency in response actions.
- Surface a small set of high-signal actions in the admin UI or API client.

### Planned features

- incident ticket export payloads
- one-click containment acknowledgment payloads
- batch owner assignment and severity updates
- email/webhook notifications for verification failures
- automated incident summaries with manifest and chain metadata

### Success criteria

- A single verification failure can produce a ready-to-paste incident payload.
- Operators can move from failure detection to containment acknowledgment quickly.
- Notifications include the batch ID, manifest hash, chain hash, and evidence path.

## Phase 5 — Multi-Environment Integration

### Objectives

- Make the export and containment system safe for staging, pre-production, and production parity.
- Support environment-specific signing keys and evidence locations.
- Keep operational behavior consistent across deployments.

### Planned features

- environment-specific manifest signing keys
- environment-prefixed batch IDs
- separate evidence directories per environment
- deployment-time verification smoke tests

### Success criteria

- Each environment can be verified independently.
- Key rotation and manifest validation work the same way in every deployment tier.
- Operators can distinguish staging evidence from production evidence at a glance.

## Feature Integration Backlog

These are the new features already introduced in the current codebase and now treated as roadmap baselines:

- signed manifest generation and verification
- replay-protected export batches
- immutable export job snapshots
- policy change history persistence
- automatic containment on verification failure
- containment evidence bundles and preserved manifest copies
- admin listing and inspection endpoints for exports and containments
- operator incident template in the documentation

## Acceptance Checklist for Future Work

Before merging any roadmap item, verify that:

- the change is backed by a real persisted record or file artifact
- the admin API exposes a supported inspection path
- the behavior is covered by automated tests
- the README or operator guide is updated when workflow steps change
- failure cases leave evidence behind rather than silently dropping context

## Suggested Next Implementation Order

1. Containment resume/resolve endpoints
2. containment audit history view
3. replay-chain health summary endpoint
4. retention policy and archival flow
5. operator automation payloads
6. multi-environment batch/evidence segregation

## Notes

This roadmap is intentionally operational. The goal is to keep VaultJS from becoming a pile of clever security primitives that nobody can run at 3 a.m. when an export chain breaks.
