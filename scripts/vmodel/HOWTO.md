# V-Model Gap-Hunt — Sigil

A four-prompt pipeline that finds gaps in the V-model traceability graph
(every requirement should have a test, every hazard should have a
constraint, every approved attack-scenario should be prevented-by
something, etc.) and produces concrete `rivet link` / `rivet add` /
schema-edit closures.

This is the V-model sibling of `scripts/mythos/`. Same Mythos discipline
(strict oracle, fresh validator, draft emit), different domain
(traceability completeness, not code bug-hunting).

## Why this is a separate pipeline from Mythos

| Axis | `scripts/mythos/` | `scripts/vmodel/` |
|---|---|---|
| Input | Source files (one per discovery agent) | Artifact gaps from `rivet validate` |
| Oracle | Failing PoC test + failing Kani harness | `rivet validate` mechanical check + schema-rule satisfaction |
| Emit | Draft `AS-N` in `artifacts/stpa/attack-scenarios.yaml` | `rivet link` command, or draft new artifact, or schema diff |
| Question | "Is there a bug in the code?" | "Is there a gap in the trail?" |
| Cycle | Discover → fix code → CI verifies | Discover → close gap → `rivet validate` re-runs |

## Prerequisites

- `rivet` installed and configured (`rivet.yaml` at repo root)
- Permission to run `rivet validate`, `rivet link`, `rivet add`

## Pipeline

### 1. Rank — what to investigate first

```
Read scripts/vmodel/rank.md and execute it. Output the JSON ranking
sorted descending. Source the gap list from `rivet validate --format json`.
```

### 2. Discover — investigate one gap per session

For each tier-5 / tier-4 gap from the ranking, in a fresh session:

```
Read scripts/vmodel/discover.md and apply it to gap {{source_id}} /
{{gap_type}}. Do not relax the oracle requirement.
```

One agent per gap is the parallelism trick. Don't sweep the whole gap
list in a single agent — diversity of resolution proposals is the goal.

### 3. Validate — fresh-session confirmation

```
Read scripts/vmodel/validate.md. Here is the proposal to validate:
<paste discover output>

Re-run rivet validate. Verify the gap still exists. Verify the
proposal's claims by reading the artifacts and schemas it cites.
```

### 4. Emit — close the gap

For confirmed proposals:

```
Read scripts/vmodel/emit.md. Here is the confirmed proposal:
<paste validator output>

Output exactly the closure artifact (rivet link command, or draft
YAML, or schema diff). Do not narrate.
```

Then run the closure (`rivet link` directly; for new artifacts,
human reviews the draft and decides).

## Resolution categories

Every confirmed gap falls into one of four:

- **`link-existing`** — both artifacts exist; close with `rivet link`.
  Highest confidence. Fully automatable.
- **`create-and-link`** — target must be drafted first. Human reviews
  draft, then links. Medium confidence.
- **`schema-rule-too-strict`** — the rule shouldn't fire here. Schema
  diff for human approval.
- **`documented-acceptance`** — absence is intentional. Field-edit
  citing the documentation.

## Pre-release V-model check

Before any release, the `rivet validate` output must show zero ERROR-level
gaps. WARNINGs are accepted with documented justification. The pre-release
checklist in AGENTS.md should reference this:

> **V-model gap pass**: `rivet validate` passes (zero ERRORs). Any
> WARNINGs are accepted with `risk-acceptance` field referencing
> documentation, OR have draft closure proposals from `scripts/vmodel/`
> queued for the next sprint.

## Gotchas

- **The mechanical check is the strong oracle.** `rivet validate`
  knows whether a link exists; LLM judgment can hallucinate.
  Always re-run rivet validate before and after any closure.
- **Don't auto-promote draft artifacts.** `create-and-link` produces
  draft artifacts that need human review. The reviewer is checking
  semantic adequacy (does this test actually cover the requirement?),
  not just structural presence.
- **Schema-relaxation proposals need extra scrutiny.** It's tempting
  to relax a rule when it fires "wrongly." Sometimes the rule is right
  and the artifact graph is wrong. Default to fixing the graph, not the
  schema.
- **`documented-acceptance` is rare and should be questioned.** If a
  hazard has no preventing constraint because "we accept this risk,"
  that decision needs a real signed-off rationale, not just a comment.

## Cycle

```
rivet validate (count ERRORs)
  → rank (vmodel/rank.md)
  → for each tier-5/4 gap: discover → validate → emit
  → rivet validate (count ERRORs again — must decrease)
  → repeat until ERRORs stable or zero
```
