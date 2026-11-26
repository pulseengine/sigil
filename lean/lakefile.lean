import Lake
open Lake DSL

package ed25519_proofs where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.16.0"

@[default_target]
lean_lib Ed25519 where
  srcDir := "."

@[default_target]
lean_lib AuditCore where
  srcDir := "."

-- Negative-control fixture for the proof gate; built explicitly in CI.
lean_lib Fixtures where
  srcDir := "."
  roots := #[`Fixtures.Planted]
