Rank traceability gaps in this repository's artifact graph by criticality.
Output JSON: `[{"source_id": "...", "gap_type": "...", "severity": N, "reason": "..."}]`,
sorted by severity descending.

Procedure:
1. Run `rivet validate --format json` and parse the output.
2. For every error, warning, and broken-cross-ref reported, classify:
   - `gap_type`: missing-link | missing-required-field | broken-target |
     missing-backlink | schema-violation | orphan-artifact
   - `severity`: 1–5 per the rubric below
   - `source_id`: the artifact id with the gap (e.g., `REQ-12`, `H-9`,
     `UCA-6`)

Severity rubric (sigil-specific, V-model criticality):

5 (safety/security-critical chain — uncovered = audit-failing gap):
  - hazard with no `prevented-by` (system-constraint missing)
  - system-constraint with no `implements` (implementation missing)
  - controller-constraint with no `implemented-by` (implementation
    missing)
  - cybersecurity-goal with no `verified-by` (cybersecurity-verification
    missing)
  - attack-scenario with no `prevented-by` AND status: approved
  - uca with no `controller-constrained-by`

4 (verification chain — needed for ASIL/SEC closure):
  - cybersecurity-req with no `cybersecurity-verification` link
  - requirement (priority `must`) with no `verified-by` (test missing)
  - threat-scenario with no `cybersecurity-goal` (TARA outcome missing)
  - design-decision with no `implemented-by` (ADR not actioned)

3 (downstream / refinement):
  - feature with no `requirement` link
  - data-flow with no `security-property` (CIA gap)
  - sub-hazard with no parent `hazard` (orphan)
  - asset with no `threat-scenario` (TARA gap)

2 (informational links):
  - requirement (priority `should` or `nice-to-have`) with no `verified-by`
  - traces-to links missing where helpful

1 (cosmetic):
  - missing optional fields, formatting issues

When ranking:
- A status: `approved` artifact missing a tier-5 link is an audit
  emergency — promote one tier above its base classification.
- A status: `draft` artifact has more latitude; promote-to-approved is
  the natural place to backfill links, so keep its base tier.
- If `rivet validate` reports a gap as severity ERROR, treat as ≥ tier 4
  regardless of artifact type. WARNINGs default to tier 3.
- Cross-reference broken targets (e.g., `links: target: H-99` where H-99
  doesn't exist) are tier 5 — the graph is structurally broken.
