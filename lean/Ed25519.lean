/-!
  # Ed25519 Algebraic Properties (CV-24)

  Lean4 formalization of Ed25519 curve operations using Mathlib.

  ## Workflow

  1. Prove theorems here in Lean4 with Mathlib
  2. Extract verified Rust code via rules_lean (Bazel)
  3. The generated Rust code provides runtime implementations
     backed by machine-checked algebraic proofs

  ## Status

  Honesty policy: every claim below states *exactly* how much of the
  proof body is mechanically checked. A `sorry` is treated as an open
  obligation and the table is required to say so. See
  `audit/2026-04-30/findings.md` C-2 for the audit context.

  - `scalarMul_mul_order`: PROVEN (depends on the `scalarMul_zero_point`
    axiom declared in this file).
  - `verification_equation_sound`: PROVEN — full mechanized proof, no
    `sorry` in the body.
  - `verification_equation_complete`: OPEN (`sorry`) — body relies on
    `basepoint_prime_order`, which is itself open. The proof sketch in
    the body is a roadmap, not a proof.
  - `cofactored_verification_sound`: PROVEN — follows from
    `verification_equation_sound`, no `sorry` in the body.
  - `basepoint_prime_order`: OPEN (`sorry`) — needs an `AddGroup`
    instance on `CurvePoint` connected to `scalarMul`, plus
    `addOrderOf B = Curve25519.ℓ`, then Mathlib's
    `addOrderOf_dvd_of_nsmul_eq_zero`.
-/

import Mathlib.GroupTheory.OrderOfElement
import Mathlib.Data.ZMod.Basic

-- Curve25519 parameters
def Curve25519.p : ℕ := 2^255 - 19
def Curve25519.ℓ : ℕ := 2^252 + 27742317777372353535851937790883648493
def Curve25519.h : ℕ := 8

-- Abstract curve point type
axiom CurvePoint : Type
axiom curveGroup : AddCommGroup CurvePoint
axiom B : CurvePoint  -- base point
axiom scalarMul : ℤ → CurvePoint → CurvePoint

notation:70 "[" n "]" P => scalarMul n P

-- Core axioms
axiom scalarMul_zero (P : CurvePoint) : [0] P = @Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero
axiom scalarMul_one (P : CurvePoint) : [1] P = P
axiom scalarMul_add (n m : ℤ) (P : CurvePoint) :
  [n + m] P = @HAdd.hAdd CurvePoint CurvePoint CurvePoint
    (@instHAdd CurvePoint curveGroup.toAddGroup.toAddMonoid.toAdd) ([n] P) ([m] P)
axiom scalarMul_mul (n m : ℤ) (P : CurvePoint) : [n * m] P = [n] ([m] P)
axiom scalarMul_neg (n : ℤ) (P : CurvePoint) :
  [-n] P = @Neg.neg CurvePoint curveGroup.toAddGroup.toNeg ([n] P)
axiom basepoint_order : [(Curve25519.ℓ : ℤ)] B = @Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero

-- Derived property: adding the identity on the right is trivial.
axiom add_zero_curvepoint (P : CurvePoint) :
  @HAdd.hAdd CurvePoint CurvePoint CurvePoint
    (@instHAdd CurvePoint curveGroup.toAddGroup.toAddMonoid.toAdd)
    P (@Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero) = P

-- Scalar multiplication of the zero point is zero.
-- This is a consequence of the group action laws: [n]O = [n]([0]P) = [n*0]P = [0]P = O.
-- We state it as an axiom to avoid threading an arbitrary witness P.
axiom scalarMul_zero_point (n : ℤ) :
  [n] (@Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero) =
  @Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero

/-! ## Scalar multiplication derived lemmas -/

/-- Scalar multiplication by -1 then adding gives identity. -/
lemma scalarMul_neg_one_add (P : CurvePoint) :
    @HAdd.hAdd CurvePoint CurvePoint CurvePoint
      (@instHAdd CurvePoint curveGroup.toAddGroup.toAddMonoid.toAdd)
      ([-1] P) ([1] P) = @Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero := by
  -- Strategy: [-1]P + [1]P = [(-1) + 1]P = [0]P = 0
  rw [← scalarMul_add (-1) 1 P]
  norm_num
  exact scalarMul_zero P

/-- Scalar multiplication distributes over multiples of ℓ: [m*ℓ]B = [m]([ℓ]B) = [m]O = O. -/
lemma scalarMul_mul_order (m : ℤ) :
    [m * (Curve25519.ℓ : ℤ)] B = @Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero := by
  -- Step 1: Factor [m*ℓ]B = [m]([ℓ]B) using scalarMul_mul
  rw [scalarMul_mul m (Curve25519.ℓ : ℤ) B]
  -- Step 2: Apply basepoint_order: [ℓ]B = O
  rw [basepoint_order]
  -- Step 3: [m]O = O by scalarMul_zero_point
  exact scalarMul_zero_point m

/-- The order of B divides ℓ (prime order subgroup). -/
theorem basepoint_prime_order :
    ∀ n : ℤ, [n] B = @Zero.zero CurvePoint curveGroup.toAddGroup.toAddMonoid.toZero →
    (Curve25519.ℓ : ℤ) ∣ n := by
  -- Strategy: B generates a cyclic subgroup of order ℓ (which is prime).
  -- By Mathlib's orderOf_dvd_of_pow_eq_one (additive version), if [n]B = O
  -- then orderOf B ∣ n. Since orderOf B = ℓ (from basepoint_order and
  -- primality of ℓ), we get ℓ ∣ n.
  --
  -- Required Mathlib lemmas:
  --   AddGroup.addOrderOf_dvd_of_nsmul_eq_zero
  --   Fact.mk (Nat.Prime Curve25519.ℓ)
  --
  -- To fully mechanize this, we would need:
  --   1. An AddGroup instance on CurvePoint connected to scalarMul
  --      (our axiom-based scalarMul is separate from the nsmul in curveGroup)
  --   2. A proof that addOrderOf B = Curve25519.ℓ, which requires showing
  --      ℓ is the *minimal* positive n with [n]B = O (primality helps here)
  --   3. Then: addOrderOf_dvd_of_nsmul_eq_zero gives the result
  sorry

/-! ## Main verification theorems -/

/-- Verification equation soundness: if s ≡ r + k*a (mod ℓ), then [s]B = R + [k]A.
    This is the core algebraic identity that makes Ed25519 verification work. -/
theorem verification_equation_sound
    (a r k s : ℤ)
    (A R : CurvePoint)
    (hA : A = [a] B)
    (hR : R = [r] B)
    (hs : s ≡ r + k * a [ZMOD (Curve25519.ℓ : ℤ)]) :
    [s] B = @HAdd.hAdd CurvePoint CurvePoint CurvePoint
      (@instHAdd CurvePoint curveGroup.toAddGroup.toAddMonoid.toAdd) R ([k] A) := by
  -- Overview:
  -- 1. From hs: ∃ m, s = r + k*a + m*ℓ
  -- 2. [s]B = [r + k*a + m*ℓ]B
  -- 3.      = [r + k*a]B + [m*ℓ]B       (by scalarMul_add)
  -- 4.      = [r + k*a]B + O             (by scalarMul_mul_order)
  -- 5.      = [r + k*a]B                 (by add_zero_curvepoint)
  -- 6.      = [r]B + [k*a]B              (by scalarMul_add)
  -- 7.      = [r]B + [k]([a]B)           (by scalarMul_mul)
  -- 8.      = R + [k]A                   (by hR, hA)
  --
  -- Step 1: Extract the modular congruence witness.
  -- Int.ModEq is: s ≡ r + k*a [ZMOD ℓ] ↔ (ℓ : ℤ) ∣ (s - (r + k*a)).
  -- Int.modEq_iff_dvd.mp gives: (↑ℓ) ∣ (s - (r + k * a)).
  -- Destructuring the divisibility yields witness m with hm.
  obtain ⟨m, hm⟩ := Int.modEq_iff_dvd.mp hs
  -- hm : s - (r + k * a) = ↑ℓ * m
  -- Derive: s = (r + k * a) + m * ℓ
  have hs_eq : s = (r + k * a) + m * (Curve25519.ℓ : ℤ) := by omega
  -- Step 2: Rewrite [s]B using the decomposition s = (r + k*a) + m*ℓ.
  rw [hs_eq]
  -- Goal: [r + k * a + m * ↑ℓ]B = R + [k]A
  -- Step 3: Distribute scalar multiplication over the outer sum.
  rw [scalarMul_add (r + k * a) (m * (Curve25519.ℓ : ℤ)) B]
  -- Goal: [r + k*a]B + [m*ℓ]B = R + [k]A
  -- Step 4: [m*ℓ]B = O via scalarMul_mul_order.
  rw [scalarMul_mul_order m]
  -- Goal: [r + k*a]B + O = R + [k]A
  -- Step 5: Eliminate + O on the left via add_zero_curvepoint.
  rw [add_zero_curvepoint ([r + k * a] B)]
  -- Goal: [r + k*a]B = R + [k]A
  -- Step 6: Distribute scalar multiplication over r + k*a.
  rw [scalarMul_add r (k * a) B]
  -- Goal: [r]B + [k*a]B = R + [k]A
  -- Step 7: Factor [k*a]B = [k]([a]B) via scalarMul_mul.
  rw [scalarMul_mul k a B]
  -- Goal: [r]B + [k]([a]B) = R + [k]A
  -- Step 8: Substitute hypotheses hA and hR.
  rw [← hA]
  -- Goal: [r]B + [k]A = R + [k]A
  rw [← hR]
  -- Goal: R + [k]A = R + [k]A  ∎

/-- Verification equation completeness: if [s]B = R + [k]A then s ≡ r + k*a (mod ℓ).
    This is the converse direction — a valid verification implies the signer knew a. -/
theorem verification_equation_complete
    (a r k s : ℤ)
    (A R : CurvePoint)
    (hA : A = [a] B)
    (hR : R = [r] B)
    (hverify : [s] B = @HAdd.hAdd CurvePoint CurvePoint CurvePoint
      (@instHAdd CurvePoint curveGroup.toAddGroup.toAddMonoid.toAdd) R ([k] A)) :
    s ≡ r + k * a [ZMOD (Curve25519.ℓ : ℤ)] := by
  -- Strategy: from hverify we get [s]B = [r]B + [k*a]B = [r + k*a]B.
  -- So [s - (r+k*a)]B = O. By basepoint_prime_order, ℓ ∣ (s - (r+k*a)),
  -- which is exactly the definition of s ≡ r+k*a (mod ℓ).
  --
  -- Proof sketch (requires basepoint_prime_order, which itself needs sorry):
  --   rw [hR, hA] at hverify
  --   -- hverify : [s]B = [r]B + [k]([a]B)
  --   rw [← scalarMul_mul k a B] at hverify
  --   -- hverify : [s]B = [r]B + [k*a]B
  --   rw [← scalarMul_add r (k * a) B] at hverify
  --   -- hverify : [s]B = [r + k*a]B
  --   -- Need: [s]B = [r+k*a]B → [s - (r+k*a)]B = O
  --   -- This requires an injectivity/cancellation axiom for scalarMul on B,
  --   -- which follows from: [s]B - [r+k*a]B = [s - (r+k*a)]B = O
  --   -- Then basepoint_prime_order gives ℓ ∣ (s - (r+k*a))
  --   -- Then Int.modEq_iff_dvd.mpr closes the goal.
  --
  -- This direction requires basepoint_prime_order (which is sorry).
  sorry

/-- Cofactored verification: [h*s]B = [h](R + [k]A).
    Used in Ed25519ctx and Ed25519ph to avoid small-subgroup attacks. -/
theorem cofactored_verification_sound
    (a r k s : ℤ)
    (A R : CurvePoint)
    (hA : A = [a] B)
    (hR : R = [r] B)
    (hs : s ≡ r + k * a [ZMOD (Curve25519.ℓ : ℤ)]) :
    [(Curve25519.h : ℤ) * s] B =
    [(Curve25519.h : ℤ)] (@HAdd.hAdd CurvePoint CurvePoint CurvePoint
      (@instHAdd CurvePoint curveGroup.toAddGroup.toAddMonoid.toAdd) R ([k] A)) := by
  -- Strategy: factor [h*s]B = [h]([s]B) by scalarMul_mul,
  -- then apply verification_equation_sound to rewrite [s]B = R + [k]A.
  rw [scalarMul_mul (Curve25519.h : ℤ) s B]
  rw [verification_equation_sound a r k s A R hA hR hs]
