import Ed25519

/-!
  # Proof audit for `Ed25519.lean`

  Lean's own report of what every declaration in the `Ed25519` module rests
  on, read by `scripts/lean-proof-gate.sh`. One line per declaration:

      decl <name> <kind> <axiom>,<axiom>,...

  where `<kind>` is `theorem`, `axiom`, `def` or `other`, and the axiom list
  is `Lean.collectAxioms` (the same data `#print axioms` prints). An open
  `sorry` shows up as `sorryAx`. The gate compares this output, not a grep of
  the source, against `lean/PROOF_LEDGER.txt`.
-/

open Lean Elab Command

#eval show CommandElabM Unit from do
  let env ← getEnv
  let some modIdx := env.getModuleIdx? `Ed25519
    | throwError "module Ed25519 not found"
  let mut lines : Array String := #[]
  for (name, info) in env.constants.toList do
    if env.getModuleIdxFor? name != some modIdx then continue
    if name.isInternal then continue
    let kind := match info with
      | .thmInfo _ => "theorem"
      | .axiomInfo _ => "axiom"
      | .defnInfo _ => "def"
      | _ => "other"
    let axioms ← liftCoreM (Lean.collectAxioms name)
    let axs := axioms.toList.map toString |>.toArray.qsort (· < ·)
    lines := lines.push s!"decl {name} {kind} {",".intercalate axs.toList}"
  for l in lines.qsort (· < ·) do
    IO.println l
