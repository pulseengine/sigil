/-!
  # Negative-control fixture for the proof gate

  Never imported by `Ed25519.lean`. CI audits this module and requires
  `scripts/lean-proof-gate.py` to reject every declaration below, so the gate
  is shown to fail on each hole on every run, not only on the day it was
  written.
-/

axiom planted_axiom : Nat

theorem planted_uses_axiom : planted_axiom = planted_axiom := rfl

private theorem planted_private : (1 : Nat) = 2 := by sorry

def planted_def : Nat := sorry
