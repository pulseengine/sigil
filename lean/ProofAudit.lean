import Ed25519
import AuditCore

/-!
  # Proof audit for `Ed25519.lean`

  Prints Lean's own axiom report for every declaration of `Ed25519` (see
  `AuditCore.lean`), read by `scripts/lean-proof-gate.py` and compared with
  `PROOF_LEDGER.txt`.
-/

#audit_module Ed25519
