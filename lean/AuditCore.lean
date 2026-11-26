import Lean

/-!
  # `#audit_module`: Lean's own report of what a module's declarations rest on

  `#audit_module M` prints one line per declaration of module `M`:

      decl <name> <kind> <axiom>,<axiom>,...

  `<kind>` is `theorem`, `axiom`, `def` or `other`; the axiom list is
  `Lean.collectAxioms` (what `#print axioms` prints). An open `sorry` shows up
  as `sorryAx`. Private declarations are reported under their user name
  (`privateToUserName?`), so a `private theorem` with a `sorry` is not hidden
  as an internal name. Read by `scripts/lean-proof-gate.py`.
-/

open Lean Elab Command

elab "#audit_module " m:ident : command => do
  let env ← getEnv
  let modName := m.getId
  let some modIdx := env.getModuleIdx? modName
    | throwError "module {modName} not found"
  let mut lines : Array String := #[]
  for (name, info) in env.constants.toList do
    if env.getModuleIdxFor? name != some modIdx then continue
    let shown := (privateToUserName? name).getD name
    if shown.isInternal then continue
    let kind := match info with
      | .thmInfo _ => "theorem"
      | .axiomInfo _ => "axiom"
      | .defnInfo _ => "def"
      | _ => "other"
    let axioms ← liftCoreM (Lean.collectAxioms name)
    let axs := axioms.toList.map toString |>.toArray.qsort (· < ·)
    lines := lines.push s!"decl {shown} {kind} {",".intercalate axs.toList}"
  for l in lines.qsort (· < ·) do
    logInfo l
