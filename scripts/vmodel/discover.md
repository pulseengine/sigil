Investigate ONE traceability gap in this repository's artifact graph and
propose a concrete resolution.

Context you must use:
- This is sigil (wsc), a security-critical cryptographic signing tool.
  Artifacts live in `artifacts/`; schemas in `schemas/`. Rivet is the
  traceability tool — see `AGENTS.md` for the full schema list (common,
  dev, stpa, stpa-sec, cybersecurity).
- Focus on ONE gap: {{source_id}} is missing {{gap_type}}.
- The artifact graph is the audit trail. A "gap" here means an audit
  evidence gap — auditors reading the trail cannot confirm the missing
  property holds.

Procedure (in order):

1. Read the source artifact in full from `artifacts/`. Understand what
   it claims, its status, its existing links, and any provenance fields.

2. Enumerate candidates via `rivet query --sexpr` BEFORE falling back
   to `rivet list` or YAML grep. The query DSL is the rivet-native way
   to filter the artifact graph; use it. Examples:

   - All UCAs not yet exploited by any attack-scenario:
     `rivet query --sexpr '(and (= type "uca") (not (linked-by "exploits")))' --format ids`
   - All requirements with no verifying test:
     `rivet query --sexpr '(and (= type "requirement") (not (linked-by "verifies")))' --format ids`
   - All hazards lacking a preventing constraint:
     `rivet query --sexpr '(and (= type "hazard") (not (linked-by "prevents")))' --format ids`

   Operator family: `and`, `or`, `not`, `implies`, `excludes`, `=`,
   `!=`, `>`, `<`, `has-tag`, `has-field`, `in`, `matches`, `contains`,
   `linked-to`, `linked-by`, `linked-from`. The semantics of the
   `linked-*` family aren't fully self-evident — when in doubt, test
   the predicate against a known artifact first (`rivet query --sexpr
   '(linked-by "exploits")' --format ids` should return UCAs/data-flows
   that ARE exploit targets).

   KNOWN GAP (rivet issue #190): there is no clean predicate for
   "this artifact is the SOURCE of an outbound link of type X." Until
   the proposed `linked-via` operator lands, that question requires
   `rivet validate --format json | jq` parsing. Document the fallback
   in the COMMAND output and link issue #190.

   Often the right candidate exists already; the gap is just an
   unrecorded link.

3. Check `safety/`, `docs/`, and CLAUDE/AGENTS for documented
   scope-outs or risk acceptances that explicitly justify the absence.
   Some gaps are intentional and documented.

4. If no candidate exists AND the gap is real: identify what new
   artifact would close it. For example:
   - Missing `verified-by` on REQ-X → propose a new `test` artifact
     drafting what the test would check, plus the path to where the
     test code SHOULD live.
   - Missing `prevented-by` on H-Y → propose a new `system-constraint`
     that inverts the hazard.

5. Distinguish four resolution categories:
   - `link-existing` — both artifacts exist; gap is just an unrecorded
     link. Highest-confidence resolution.
   - `create-and-link` — the target artifact must be created (draft);
     then linked. Medium confidence — needs human review of the draft.
   - `schema-rule-too-strict` — the rule fires but the gap isn't
     meaningful for this artifact type/context. Propose schema relaxation.
   - `documented-acceptance` — the absence is intentional; the
     artifact needs a `risk-acceptance` field or a comment citing the
     documenting reference.

Oracle requirement (non-negotiable):
For every proposal you make you MUST produce both:
  (1) The exact `rivet link` or `rivet add` command that would close the
      gap (or the exact field+value to add for documented acceptance).
      Use `--status draft` for any new artifact.
  (2) Verification that the gap is REAL right now: paste the relevant
      lines from `rivet validate --format json` showing the gap. After
      your proposed action, the gap should disappear from
      `rivet validate` output. Show this expected delta — what the next
      `rivet validate` run would no longer report.

If you cannot produce both, the proposal does not count. Do not emit
speculative gap-closures. Hallucinations are more expensive than
silence.

Output format:
- SOURCE: {{source_id}} (type, status, title)
- GAP: {{gap_type}} per `rivet validate` output (paste the line)
- INVESTIGATION: one paragraph — what you searched, what you found
- RESOLUTION CATEGORY: link-existing | create-and-link |
  schema-rule-too-strict | documented-acceptance
- COMMAND: fenced shell block — the exact `rivet link` / `rivet add` /
  field-edit
- EXPECTED DELTA: the line that would no longer appear in
  `rivet validate` after the action
- CONFIDENCE: high (link-existing) | medium (create-and-link) |
  needs-human-judgment (schema | acceptance)
