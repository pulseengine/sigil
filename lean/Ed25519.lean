/-!
  # Ed25519 Algebraic Properties (CV-24)

  Lean4 formalization of Ed25519 curve operations using Mathlib.

  ## Workflow

  1. Prove theorems here in Lean4 with Mathlib
  2. Extract verified Rust code via rules_lean (Bazel)
  3. The generated Rust code provides runtime implementations
     backed by machine-checked algebraic proofs

  ## Status

  - `verification_equation_sound`: proof sketch, needs Mathlib ZMod
  - `verification_equation_complete`: needs prime-order argument
  - `cofactored_verification_sound`: follows from above
  - `basepoint_prime_order`: needs Mathlib OrderOf
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

-- Scalar multiplication of the zero point is zero (needed for scalarMul_mul_order).
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
  -- Strategy: [m*ℓ]B = [m]([ℓ]B) = [m]O = O
  -- Step 1: Factor using scalarMul_mul
  rw [scalarMul_mul m (Curve25519.ℓ : ℤ) B]
  -- Step 2: Apply basepoint_order: [ℓ]B = O
  rw [basepoint_order]
  -- Step 3: [m]O = O (scalar mul of identity is identity)
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
  -- Proof strategy:
  -- 1. From hs: ∃ m, s = r + k*a + m*ℓ
  -- 2. [s]B = [r + k*a + m*ℓ]B
  -- 3.      = [r]B + [k*a]B + [m*ℓ]B   (by scalarMul_add)
  -- 4.      = R + [k]([a]B) + [m]([ℓ]B) (by scalarMul_mul, hR)
  -- 5.      = R + [k]A + [m]O            (by basepoint_order, hA)
  -- 6.      = R + [k]A                   (by add_zero)
  --
  -- Detailed proof:
  -- Step 1: Extract the modular congruence witness.
  -- Int.ModEq gives us: ∃ m, s - (r + k*a) = m * ℓ, i.e., s = r + k*a + m*ℓ.
  obtain ⟨m, hm⟩ := (Int.modEq_iff_dvd.mp hs)
  -- hm : ↑ℓ ∣ (s - (r + k * a)), so ∃ m, s - (r + k*a) = m * ℓ
  -- which means s = (r + k*a) + m * ℓ
  --
  -- Step 2: Rewrite [s]B using the decomposition.
  -- have hs_eq : s = (r + k * a) + m * (Curve25519.ℓ : ℤ) := by omega
  -- rw [hs_eq]
  --
  -- Step 3: Distribute scalar multiplication.
  -- rw [scalarMul_add (r + k * a) (m * ↑Curve25519.ℓ) B]
  -- rw [scalarMul_add r (k * a) B]
  --
  -- Step 4: Factor [k*a]B = [k]([a]B) and [m*ℓ]B = [m]([ℓ]B).
  -- rw [scalarMul_mul k a B]
  -- rw [scalarMul_mul m (↑Curve25519.ℓ) B]
  --
  -- Step 5: Apply basepoint_order and hypotheses.
  -- rw [basepoint_order]          -- [ℓ]B ↦ O
  -- rw [scalarMul_zero_point m]   -- [m]O ↦ O (needs helper lemma)
  -- rw [← hA]                     -- [a]B ↦ A
  -- rw [← hR]                     -- [r]B ↦ R
  --
  -- Step 6: R + [k]A + O = R + [k]A by add_zero.
  -- rw [add_zero_curvepoint (R + [k]A)]  -- ... + O ↦ ...
  sorry

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
  -- This direction requires injectivity mod ℓ, i.e., basepoint_prime_order.
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
