# Contributing to VaultJS Advanced Agent Features

**Updated:** 2026-06-19 | **Status:** Ready for team participation

---

## How to Get Involved

### 1. Read the Docs (30 min)
- Start with **INDEX.md** for navigation
- Skim **QUICK_REFERENCE.md** for high-level overview
- Deep dive into features that interest you in **ADVANCED_AGENT_FEATURES.md**

### 2. Join the Discussion (Async)
- Comment on GitHub issues with label `agent-feature-discussion`
- Ask questions about design decisions (see "Open Questions" in each feature)
- Propose clarifications or alternative approaches

### 3. Propose a Feature (2 hours)
1. Copy **RFC_TEMPLATE.md** to a new file: `roadmap/rfc/AGENT-NNNN.md`
2. Fill in all sections (follow the template structure)
3. Open a pull request with label `rfc` + `feature-proposal`
4. Address feedback from reviewers
5. When approved, feature enters implementation queue

### 4. Implement a Feature (2–4 weeks depending on scope)
1. Start with an approved RFC
2. Create a feature branch: `feature/agent-NNNN-name`
3. Implement following RFC design
4. Add comprehensive tests:
   - Unit tests (signal calculations, edge cases)
   - Integration tests (end-to-end flows)
   - Load tests (latency, throughput)
   - Security tests (auth, signing, audit)
5. Update documentation
6. Open PR and request review
7. Iterate on feedback
8. Merge when all checks pass

### 5. Review & Approve
- Security leads: Review "Security & Privacy" sections in RFC
- Ops leads: Review "Operational Runbook" and troubleshooting
- Tech leads: Review "Design & Implementation" and testing strategy
- Product: Review success criteria and user impact

### 6. Deploy & Learn
- Use **QUICK_REFERENCE.md** deployment checklist
- Follow canary strategy: 1% → 5% → 25% → 100%
- Monitor success metrics (see RFC section 5)
- Document learnings and update RFC with lessons

---

## Role-Specific Guides

### For Product Managers
**Goal:** Prioritize features and track progress

1. Review ADVANCED_AGENT_FEATURES.md Part 7 – "Future Explorations"
2. Evaluate feasibility (effort) vs. impact (user pain)
3. Suggest new features via GitHub issue with label `feature-request`
4. Track implementation status using GitHub project board (milestones: Alpha, Beta, Production)
5. Gather operator feedback post-launch

**How to request a feature:**
```
Title: [Feature Request] AI-powered anomaly clustering
Description:
- Current: Anomaly scores are threshold-based
- Desired: Automatically group similar anomalies into clusters
- Why: Operators want to understand attack patterns, not individual events
- Effort estimate: [TBD after initial investigation]
- Success would mean: 90% of anomalies correctly grouped, < 5% false groupings
```

---

### For Security Architects
**Goal:** Validate security properties and audit integrity

1. Review ADVANCED_AGENT_FEATURES.md Part 1, 3, and 6 (detection, audit, governance)
2. For each feature, check:
   - [ ] Attack surface is documented
   - [ ] Audit trail is immutable and complete
   - [ ] Encryption/signing used where needed
   - [ ] Compliance implications (SOC 2, GDPR, etc.) understood
3. Use RFC section 6 ("Security & Privacy") as checklist
4. Approve or request changes in RFC review

**Security checklist template:**
```
## Security Review – Feature 1.1 (Anomaly Scoring)

- [ ] Scores cannot be manipulated by attacker
- [ ] Calculation is side-channel resistant
- [ ] Audit trail covers all scoring decisions
- [ ] Escape paths are properly authorized
- [ ] No PII in anomaly records
- [ ] Grace period doesn't weaken token validation
```

---

### For Operators & SREs
**Goal:** Ensure features are operationally sound and runnable

1. Review QUICK_REFERENCE.md ("Quick Deployment Checklist" + "Tuning & Troubleshooting")
2. For each feature, validate:
   - [ ] Runbook is clear and tested
   - [ ] Alerts are meaningful (not noisy)
   - [ ] Rollback procedure works
   - [ ] Deployment can be automated
3. Test in staging before production rollout
4. Document operational procedures and incident playbooks
5. Provide feedback on RFC's "Operational Runbook" section

**Operational sign-off template:**
```
## Ops Approval – Feature 2.1 (Fallback Orchestration)

- [x] Runbook tested in staging (✓ passing)
- [x] Fallback latency acceptable (✓ p99 < 150ms)
- [x] Circuit breaker behavior correct (✓ auto-recovery works)
- [x] Monitoring & alerts configured (✓ in place)
- [x] Rollback procedure rehearsed (✓ < 30s)
- [x] On-call team trained (✓ 3x runthrough)
Status: Ready for production
```

---

### For Implementation Teams
**Goal:** Build features according to spec with high quality

1. Start with an approved RFC (don't skip this step!)
2. Create implementation plan breaking RFC into tasks:
   - API endpoints
   - Data model & migrations
   - Audit logging
   - Tests (unit, integration, load)
   - Documentation updates
3. Set up feature branch and start coding
4. Use RFC as contract – any deviation should update RFC
5. Regular syncs with product + security + ops (weekly)
6. After implementation:
   - All tests pass (coverage > 80%)
   - Load tests validate latency budgets
   - Documentation is complete
   - Runbook has been dry-run by ops team
7. Open PR with link to RFC
8. Address feedback from all stakeholders
9. Deploy with canary strategy

**Implementation checklist:**
```
## Feature 1.1 – Anomaly Scoring Implementation

- [ ] API endpoints complete (`POST /admin/agents/anomaly-detection/config`, etc.)
- [ ] Database schema created (anomaly_scores table, indexes)
- [ ] Audit logging integrated (decision audit events)
- [ ] Unit tests pass (signal calc, weighting, thresholds)
- [ ] Integration tests pass (end-to-end flow)
- [ ] Load tests pass (< 50ms, 10k req/s)
- [ ] Security tests pass (no score manipulation, no PII leak)
- [ ] Documentation updated (admin guide, API reference)
- [ ] Runbook validated by ops team
- [ ] Feature flag implemented (disable without code change)
Status: Ready for staging deployment
```

---

### For Tech Leads
**Goal:** Ensure architectural integrity and quality

1. Review RFC before implementation approval
   - Check all sections complete
   - Validate design tradeoffs
   - Identify integration risks
2. During implementation:
   - Code review for quality and security
   - Design review for any deviations from RFC
   - Architecture review for cross-feature interactions
3. After implementation:
   - Verify test coverage
   - Check audit logging
   - Validate load test results
   - Approve for staging deployment

**Tech lead review template:**
```
## Tech Review – Feature 1.1

Architecture:
- [x] Design follows existing patterns
- [x] New tables/indexes are necessary and efficient
- [x] API contract is stable and documented

Implementation Quality:
- [x] Tests cover happy path + edge cases + failures
- [x] Audit logging is complete (decisions, errors, timing)
- [x] Error handling is explicit (no silent failures)
- [x] Code is readable with comments where needed

Integration:
- [x] No conflicts with other features
- [x] Hooks into auth-server correctly
- [x] Maintains backward compatibility

Performance:
- [x] Latency budget met (< 50ms)
- [x] Throughput target met (10k req/s)
- [x] Memory footprint reasonable

Approval: LGTM (ready for staging)
```

---

## Decision-Making Framework

When discussing a feature proposal, use this framework to reach consensus:

### Dimensions to Evaluate

| Dimension | Questions | Rating |
|-----------|-----------|--------|
| **Impact** | How much user/operator pain does this solve? How many deployments benefit? | High/Medium/Low |
| **Effort** | How much engineering time? How complex? How many moving parts? | High/Medium/Low |
| **Risk** | What's the failure mode? What's the blast radius? | High/Medium/Low |
| **Dependencies** | How many other features must complete first? | High/Medium/Low |
| **Alignment** | How well does this align with VaultJS goals? | Strong/Moderate/Weak |

### Prioritization Matrix

```
            Low Effort    |    High Effort
High Impact     [PRIORITY 1] | [PRIORITY 2]
Low Impact      [PRIORITY 3] | [PRIORITY 4]
```

**Example:**
- Feature 1.1 (Anomaly): High impact (solves false positives), medium effort, medium risk → **Priority 1**
- Feature 7.2 (Blockchain): Low impact (compliance edge case), high effort, high risk → **Priority 4**

---

## Communication Norms

### Sync Meetings (Optional but Recommended)
- **Weekly architecture sync:** Thursdays 2 PM UTC
- **Agenda:** RFC approvals, implementation blockers, cross-feature coordination
- **Duration:** 30–45 min
- **Attendees:** Whoever wants to participate (recorded)

### Async Communication
- **Issues:** For discussions, decisions, tracking
- **Pull requests:** For code review and approval
- **Markdown docs:** For specs, design docs, runbooks
- **Labels:** Use consistently (rfc, agent-feature-discussion, phase-alpha, bug, etc.)

### Response Time Expectations
- Urgent (label: urgent): 24 hours
- Normal (no label): 2–3 business days
- FYI (label: fyi): no deadline

---

## Quality Standards

All features must meet these standards before approval:

### Code Quality
- ✓ Tests pass (unit, integration, load)
- ✓ Test coverage > 80%
- ✓ Code follows existing patterns
- ✓ No unhandled errors
- ✓ Security reviewed

### Operational Quality
- ✓ Audit trail is complete
- ✓ Metrics are exported for monitoring
- ✓ Runbook is tested and clear
- ✓ Rollback procedure works
- ✓ Ops team sign-off obtained

### Documentation Quality
- ✓ API contract documented
- ✓ Configuration examples provided
- ✓ Troubleshooting guide included
- ✓ Incident playbooks provided
- ✓ Links from README

### Design Quality
- ✓ RFC complete and approved
- ✓ Design tradeoffs documented
- ✓ Open questions resolved
- ✓ Integration with other features verified
- ✓ Security implications addressed

---

## Onboarding Checklist for New Contributors

If you're new to VaultJS agent features, follow this checklist:

- [ ] Clone/checkout the repository
- [ ] Read README.md (project overview)
- [ ] Read INDEX.md (documentation index)
- [ ] Pick one feature from QUICK_REFERENCE.md and read it deeply
- [ ] Comment on one open discussion or RFC with thoughtful feedback
- [ ] Review one RFC (practice using RFC_TEMPLATE.md as checklist)
- [ ] Implement a small feature or bugfix (not from agent features – something else)
- [ ] Propose an RFC for a new feature idea
- [ ] Implement a full agent feature (Alpha phase)
- [ ] Celebrate! 🎉

---

## Common Pitfalls & How to Avoid Them

### Pitfall 1: Skipping the RFC
**Problem:** Starting implementation without approved design  
**Result:** Wrong solution, wasted effort, rework  
**Avoidance:** Always get RFC approved first. RFC is not bureaucracy; it's insurance.

### Pitfall 2: Forgetting Audit Logging
**Problem:** Feature works but leaves no trail  
**Result:** Security team rejects; compliance issues  
**Avoidance:** Audit logging is a first-class requirement. Plan it from RFC phase.

### Pitfall 3: Over-Engineering
**Problem:** Building for every edge case and future feature  
**Result:** Delayed delivery, harder maintenance  
**Avoidance:** Build to RFC spec. Future improvements come later via new RFCs.

### Pitfall 4: Insufficient Testing
**Problem:** Feature works in ideal case, breaks under load or failure  
**Result:** Production incident, emergency fixes  
**Avoidance:** Test happy path, sad path, load, security. Use success criteria from RFC.

### Pitfall 5: Missing Runbook
**Problem:** Feature shipped but ops team doesn't know how to run it  
**Result:** Incidents aren't handled; operators page on-call at 3 AM  
**Avoidance:** Runbook must be approved by ops team before staging deployment.

---

## Getting Help

### Questions?
- Comment on relevant GitHub issue
- Ask in weekly architecture sync
- Ping someone in Slack (or email if urgent)

### Stuck?
- Review existing RFCs for similar features (copy patterns)
- Ask tech lead for design guidance
- Request pair programming session

### Feedback?
- Comment on PRs with constructive feedback
- Suggest improvements to RFC_TEMPLATE.md
- Propose better terminology or organization

---

## Thank You!

VaultJS advanced agent features are ambitious. They'll only succeed with input and effort from many people.

**Your contribution matters:**
- Architects: Validate designs
- Security: Catch vulnerabilities
- Operators: Ensure runability
- Engineers: Build with quality
- Product: Prioritize impact

---

**Contribution Guide Version:** 1.0  
**Updated:** 2026-06-19  
**Status:** Ready for team use
