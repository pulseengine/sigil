You are emitting the actual gap closure for a confirmed proposal. The
emit step for V-model gaps is different from Mythos bug-emit: instead
of drafting an artifact for human review, you are RUNNING THE COMMAND
that closes the gap (or producing the YAML draft for a new artifact).

Input:
- Confirmed proposal (below)
- Validator verdict: `confirmed`
---
{{confirmed_proposal}}
---

Rules:

1. For `link-existing` resolutions:
   - Run the exact `rivet link SOURCE -t <type> --target TARGET` command.
   - After the command, run `rivet validate --format json` and confirm
     the gap line disappears from the output.
   - If the command errors (target doesn't exist, link-type invalid,
     etc.), DO NOT retry with a different link-type. Report the error
     and escalate to human.

2. For `create-and-link` resolutions:
   - Output the YAML draft for the new artifact, ready to paste into the
     correct file in `artifacts/<schema>/`. Use `status: draft` always.
   - Then output the `rivet link` command that would link the source to
     the new artifact's ID once it's added.
   - Do NOT execute `rivet add` directly — the new artifact requires
     human review of the draft text before it joins the audit trail.

3. For `schema-rule-too-strict` resolutions:
   - Output the proposed change to the relevant schema file in
     `schemas/`, as a unified diff.
   - Do NOT apply the change; schema changes need human approval.

4. For `documented-acceptance` resolutions:
   - Output the field-edit YAML that would add the `risk-acceptance`
     field (or whatever the schema calls the documented-exception
     mechanism) to the source artifact.
   - Cite the documentation reference as part of the field value.

5. Closure invariant: for any resolution that lands a change, the next
   `rivet validate --format json` MUST show one fewer gap. If it
   doesn't, the proposal failed and must be reverted.

Output exactly one of:
- The `rivet link` command + the post-command `rivet validate` delta
- The YAML draft + the link command + a note about human review
- The schema diff + a note about human approval needed
- The field-edit YAML + the documentation reference

Nothing else. No prose summary, no metadata.
