I have received the following gap-closure proposal. Can you please
confirm whether it should be applied?

Proposal:
---
{{proposal}}
---

You are a fresh validator with no stake in the proposal. Your job is to
reject hallucinated gap-closures and accept only those whose oracle
holds. A false positive here pollutes the audit trail with bogus links;
a false negative leaves a real gap unfixed.

Procedure:
1. Run `rivet validate --format json` and confirm the gap cited in the
   proposal STILL EXISTS today. If it doesn't, the proposal is stale —
   reply `VERDICT: stale` and stop.
2. Read the source artifact from `artifacts/` to confirm the proposal's
   claims about its current state.
3. For `link-existing` proposals: read the target artifact and confirm
   that linking source → target via the proposed link-type satisfies
   the schema's link-type semantics. The link-types table is in
   `AGENTS.md` (Rivet Artifact Reference section). If the link-type is
   wrong for the source/target type pair, reply `VERDICT: wrong-link-type`
   and explain.
4. For `create-and-link` proposals: read the proposed draft artifact
   field-by-field. Reject if it duplicates an existing artifact, fails
   schema validation, or makes claims the source artifact doesn't
   support.
5. For `schema-rule-too-strict` proposals: read the relevant schema
   file in `schemas/`. Confirm the rule actually fires on this
   artifact AND that relaxing it would not weaken the audit trail
   elsewhere.
6. For `documented-acceptance` proposals: confirm the cited
   documentation actually exists and actually justifies the absence.
   Read `safety/`, `docs/security/`, or wherever the proposal points.
   "Documented" means a human-readable rationale, not just a TODO
   comment.
7. Apply the COMMAND from the proposal in dry-run mode if possible, or
   manually verify it would have the EXPECTED DELTA the proposal
   claims. If the delta differs, the proposal is wrong.

Output:
- `VERDICT: confirmed | rejected | stale | needs-human-judgment`
- `REASON:` one paragraph explaining the verdict, citing specific
  artifacts and schema rules.
- For `confirmed`: state the next step (apply the command, then re-run
  rivet validate to confirm closure).
