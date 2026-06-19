# VaultJS Agent Feature RFC Template

Use this template to propose, discuss, and refine individual advanced agent features before implementation.

---

## RFC Metadata

| Field | Value |
|-------|-------|
| **RFC Number** | `AGENT-XXXX` (auto-assigned) |
| **Feature Name** | [e.g., "Intelligent Anomaly Scoring with Predictive Containment"] |
| **Proposed by** | [Your name/team] |
| **Status** | Draft / Discussion / Accepted / Implemented / Archived |
| **Target Phase** | Alpha / Beta / Production / Advanced |
| **Last Updated** | YYYY-MM-DD |

---

## 1. Summary

**One-paragraph overview** of the problem, proposed solution, and expected impact.

Example:
> Today's risk scoring is static and threshold-based. A spike in failed attempts looks identical to a coordinated attack. We propose a multi-factor anomaly scoring system with predictive containment stages that allow operators to apply graduated responses (throttle → challenge → isolate) instead of all-or-nothing pauses. Expected outcome: 50% reduction in false-positive containment events and < 5% detection latency.

---

## 2. Motivation

### Problem Statement
Describe the real-world pain point or limitation this RFC addresses.

**Criteria for good problem statements:**
- Grounded in production incidents or customer feedback
- Quantified if possible (e.g., "manual steps take 30min", "false positive rate is 15%")
- Aligned with VaultJS security or operational goals

### Success Criteria
What does success look like? Define 2–4 measurable outcomes.

Examples:
- ✓ False positive rate < 2% on benign bulk operations
- ✓ Mean time to detection < 5 seconds on replay-chain breaks
- ✓ Operators can adjust weights without code deployment
- ✓ Export manifests include anomaly score snapshots

---

## 3. Design & Implementation

### API Contract
Show the proposed HTTP endpoints, webhooks, or config schemas.

**Example:**
```bash
POST /admin/agents/anomaly-detection/config
{
  "modelVersion": "v2-predictive",
  "signals": [
    { "type": "replay_rotation_drift", "weight": 0.3 },
    { "type": "geo_velocity", "weight": 0.25 }
  ],
  "stageThresholds": {
    "observe": 0.35,
    "softThrottle": 0.55,
    "isolate": 0.95
  }
}
```

### Data Model
Document new database tables, cache structures, or audit records.

**Example:**
```sql
CREATE TABLE anomaly_scores (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL,
  user_id TEXT,
  score REAL,
  signals JSON,  -- {"replay_drift": 0.3, "geo_velocity": 0.25}
  stage TEXT,    -- observe, softThrottle, isolate
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (batch_id) REFERENCES export_jobs(batch_id)
);
```

### Audit Trail
How will this feature be audited? What immutable records must be kept?

**Example:**
- Anomaly score calculations logged with per-signal contribution
- Stage transitions trigger audit events
- Auto-escalation decisions include confidence % and batch IDs

### Fallback & Degradation
What happens if this feature fails or is disabled?

**Example:**
- If anomaly agent is unavailable, fall back to static threshold scoring
- If predictive model fails to load, use last-known good version
- Operators can disable specific signals without disabling entire agent

---

## 4. Affected Components

List VaultJS packages, apps, or external systems impacted.

**Example:**
- `packages/auth-server` – adds anomaly calculation middleware
- `packages/validation-service` – decision engine integrates scores
- `infra/db` – new audit tables and indexes
- Admin API – new `/admin/agents/anomaly-detection/*` endpoints
- External: SIEM webhooks, ticketing systems (optional integration)

---

## 5. Security & Privacy Considerations

### Security Implications
- Does this agent introduce new attack surfaces?
- Can an attacker manipulate scores to evade detection?
- Are anomaly calculations side-channel resistant?

### Privacy
- Does this collect or store PII? If so, how?
- How long are user-specific anomaly records retained?
- Can operators export anomaly data without exposing user identity?

### Compliance
- Does this impact SOC 2, GDPR, or other regulatory obligations?
- How are automated decisions audited for fairness and transparency?

---

## 6. Testing Strategy

### Unit Tests
- Anomaly score calculation with known inputs → expected outputs
- Signal weighting edge cases (zero weight, invalid range)
- Stage threshold boundaries

### Integration Tests
- End-to-end: user request → anomaly score → containment stage
- Fallback activation when agent unavailable
- Audit event generation and persistence

### Load Tests
- Anomaly calculation latency under 10k req/s
- Database indexes optimize query performance
- Memory footprint of in-memory signal cache

### Security Tests
- Score manipulation attempts (invalid signals, boundary values)
- Unauthorized access to admin config endpoints
- Anomaly data leakage in error messages or logs

---

## 7. Operational Runbook

### Deployment
- Feature flag to enable/disable without code deploy
- Configuration validation before activation
- Canary rollout to 1% → 5% → 25% → 100% traffic

### Monitoring & Alerting
- Alert if anomaly agent latency > 100ms (P99)
- Alert if score variance spike (potential model drift)
- Alert if stage escalation rate > 5% (possible tuning issue)

### Incident Playbook
**Scenario:** Anomaly scores suddenly spiking, causing false-positive containment.

**Diagnosis:**
1. Check if signals are weighted correctly
2. Review recent policy changes
3. Verify no data corruption in audit tables

**Resolution:**
1. Temporarily lower stage thresholds
2. Review and adjust signal weights
3. Rollback to previous model version if needed

### Rollback
- Disable agent and revert to static threshold scoring
- Keep anomaly audit records for forensics
- Timeline: < 5 minutes

---

## 8. Migration & Compatibility

### Backwards Compatibility
- Does this break existing token format or session model?
- Can old clients (no context headers) still authenticate?
- Deprecation path if changing API contract?

### Data Migration
- Do existing export batches need re-scoring?
- How to handle sessions created before feature deployment?

### Upgrade Path
- Feature flag enabled by default in new deployments?
- Operator choice to opt-in for existing deployments?

---

## 9. Performance & Scalability

### Latency Budget
- Anomaly calculation: < 50ms (on critical path) or < 100ms (async)
- Signal fetching from cache/DB: < 10ms
- Stage decision: < 5ms

### Throughput
- Process 10k token requests/sec with anomaly scoring
- Handle 100k audit records/day without degradation

### Storage
- Estimated DB growth: ~X GB/year (based on metrics)
- Retention policy: keep recent scores for compliance window

---

## 10. Documentation

### README Updates
- New admin endpoints documented
- Configuration examples
- Troubleshooting guide

### Operator Guide
- How to interpret anomaly scores
- How to tune weights and thresholds
- How to respond to false positives

### Developer Notes
- Signal calculation algorithms
- Caching strategy
- Integration points with other agents

---

## 11. Dependencies & Blockers

### Internal Dependencies
- Feature A must be completed first
- Database migration required in Phase X

### External Dependencies
- Requires Redis (or can gracefully degrade)
- Optional integration with external threat intel service

### Known Blockers
- None identified yet (or "Awaiting decision on X")

---

## 12. Alternatives Considered

### Alternative 1: Static Threshold Scoring (Status Quo)
**Pros:** Simple, no model training  
**Cons:** False positives/negatives, inflexible  
**Decision:** Insufficient for production use case

### Alternative 2: Fully Outsourced ML Service
**Pros:** Offload ML infrastructure  
**Cons:** Introduces external dependency, latency, privacy concerns  
**Decision:** Prefer in-process scoring for latency and control

---

## 13. Open Questions & Decisions

- [ ] Should anomaly agent run synchronously (on critical path) or async?
- [ ] Multi-tenancy: separate score buckets per tenant or shared model?
- [ ] Initial model version: simple weighted sum, or neural net?
- [ ] Score retention: 7 days, 30 days, or 90 days?

**Decisions Made:**
- ✓ Run synchronously (< 50ms budget acceptable)
- ✓ Single shared model initially; multi-tenant later if needed
- ✓ Start with weighted sum; explore ML in future phase
- ✓ Retain scores for 90 days

---

## 14. Sign-Off & Approval

| Role | Name | Status | Date |
|------|------|--------|------|
| **Feature Owner** | [Name] | [ ] Approve | [ ] |
| **Security Lead** | [Name] | [ ] Approve | [ ] |
| **Ops Lead** | [Name] | [ ] Approve | [ ] |
| **Tech Lead** | [Name] | [ ] Approve | [ ] |

---

## 15. Changelog & Revisions

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | [Author] | Initial RFC |
| 1.1 | YYYY-MM-DD | [Author] | Addressed feedback on multi-tenancy |

---

## References

- VaultJS Advanced Agent Features (`ADVANCED_AGENT_FEATURES.md` – Section 1.1)
- Token Engine (`packages/token-engine/README.md`)
- Validation Service (`packages/validation-service/README.md`)
- Related RFCs: [AGENT-0001], [AGENT-0002]

---

## Appendix: Sample Configuration

```json
{
  "modelVersion": "v2-predictive",
  "signals": [
    {
      "type": "replay_rotation_drift",
      "weight": 0.3,
      "description": "Deviation from expected token rotation counter",
      "threshold": 3,
      "cacheTTL": 300000
    },
    {
      "type": "geo_velocity",
      "weight": 0.25,
      "description": "Impossible travel speed between auth locations",
      "threshold": 800,
      "cacheTTL": 600000
    },
    {
      "type": "device_fp_churn",
      "weight": 0.25,
      "description": "Fingerprint entropy over time window",
      "threshold": 4,
      "cacheTTL": 1800000
    },
    {
      "type": "policy_violation_rate",
      "weight": 0.2,
      "description": "Percentage of requests violating active policies",
      "threshold": 0.15,
      "cacheTTL": 60000
    }
  ],
  "stageThresholds": {
    "observe": 0.35,
    "softThrottle": 0.55,
    "hardThrottle": 0.70,
    "challenge": 0.85,
    "isolate": 0.95
  },
  "escapePaths": [
    {
      "pattern": "authenticated_admin_override",
      "exemptStages": ["isolate"],
      "reason": "Admins need access during incidents"
    },
    {
      "pattern": "known_vpn_range",
      "exemptStages": ["challenge", "isolate"],
      "reason": "Corporate VPN has static IP and can be whitelisted"
    }
  ]
}
```

---

**Document Version:** 1.0  
**Last Revised:** 2026-06-19  
**Template Status:** Ready to use  
**Maintained by:** VaultJS Core Team
