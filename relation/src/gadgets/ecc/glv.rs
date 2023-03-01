// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use crate::{
    errors::CircuitError,
    gadgets::ecc::{MultiScalarMultiplicationCircuit, PointVariable},
    BoolVar, Circuit, PlonkCircuit, Variable,
};
use ark_ec::{
    twisted_edwards::{Projective, TECurveConfig},
    CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use jf_utils::field_switching;
use num_bigint::{BigInt, BigUint};

use super::Point;

// phi(P) = lambda*P for all P
// constants that are used to calculate phi(P)
// see <https://eprint.iacr.org/2021/1152>
const COEFF_B: [u8; 32] = [
    180, 16, 37, 23, 77, 1, 15, 238, 214, 244, 154, 13, 119, 18, 167, 46, 136, 26, 81, 99, 58, 13,
    240, 97, 165, 38, 132, 130, 139, 242, 201, 82,
];

const COEFF_C: [u8; 32] = [
    61, 11, 101, 223, 108, 128, 92, 81, 233, 244, 54, 255, 207, 171, 86, 132, 7, 209, 23, 108, 253,
    110, 124, 169, 195, 87, 84, 134, 207, 36, 198, 108,
];
/// The lambda parameter for decomposition.
const LAMBDA: [u8; 32] = [
    5, 223, 131, 135, 64, 33, 61, 209, 110, 5, 165, 112, 185, 157, 196, 207, 43, 199, 56, 43, 86,
    73, 248, 237, 147, 164, 57, 74, 220, 243, 180, 19,
];
/// Lower bits of Lambda, s.t. LAMBDA = LAMBDA_1 + 2^128 LAMBDA_2
const LAMBDA_1: [u8; 32] = [
    5, 223, 131, 135, 64, 33, 61, 209, 110, 5, 165, 112, 185, 157, 196, 207, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// Higher bits of Lambda, s.t.
// LAMBDA = LAMBDA_1 + 2^128 LAMBDA_2
const LAMBDA_2: [u8; 32] = [
    43, 199, 56, 43, 86, 73, 248, 237, 147, 164, 57, 74, 220, 243, 180, 19, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];
/// Lower bits of r, s.t. r = r1 +
// 2^128 r2
const R1: [u8; 32] = [
    225, 231, 118, 40, 181, 6, 253, 116, 113, 4, 25, 116, 0, 135, 143, 255, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];
/// Higher bits of r, s.t. r = r1
// + 2^128 r2
const R2: [u8; 32] = [
    0, 118, 104, 2, 2, 118, 206, 12, 82, 95, 103, 202, 212, 105, 251, 28, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];

const COEFF_N11: [u8; 32] = [
    31, 24, 137, 151, 74, 249, 2, 75, 142, 146, 230, 75, 0, 226, 95, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];

const COEFF_N12: [u8; 32] = [
    68, 31, 214, 35, 26, 89, 226, 248, 93, 143, 94, 229, 238, 179, 20, 8, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];

const COEFF_N21: [u8; 32] = [
    136, 62, 172, 71, 52, 178, 196, 241, 187, 30, 189, 202, 221, 103, 41, 16, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const COEFF_N22: [u8; 32] = [
    194, 207, 237, 144, 106, 13, 250, 41, 227, 113, 50, 40, 0, 165, 47, 170, 0, 118, 104, 2, 2,
    118, 206, 12, 82, 95, 103, 202, 212, 105, 251, 28,
];

// GLV related gates
impl<F> PlonkCircuit<F>
where
    F: PrimeField,
{
    /// Perform GLV multiplication in circuit (which costs a few less
    /// constraints).
    pub fn glv_mul<P: TECurveConfig<BaseField = F>>(
        &mut self,
        scalar: Variable,
        base: &PointVariable,
    ) -> Result<PointVariable, CircuitError> {
        self.check_var_bound(scalar)?;
        self.check_point_var_bound(base)?;

        let (s1_var, s2_var, s2_sign_var) = scalar_decomposition_gate::<_, P, _>(self, &scalar)?;

        let endo_base_var = endomorphism_circuit::<_, P>(self, base)?;
        multi_scalar_mul_circuit::<_, P>(self, base, s1_var, &endo_base_var, s2_var, s2_sign_var)
    }
}

/// The circuit for 2 base scalar multiplication with scalar bit length 128.
fn multi_scalar_mul_circuit<F, P>(
    circuit: &mut PlonkCircuit<F>,
    base: &PointVariable,
    scalar_1: Variable,
    endo_base: &PointVariable,
    scalar_2: Variable,
    scalar_2_sign_var: BoolVar,
) -> Result<PointVariable, CircuitError>
where
    F: PrimeField,
    P: TECurveConfig<BaseField = F>,
{
    let endo_base_neg = circuit.inverse_point(endo_base)?;
    let endo_base =
        circuit.binary_point_vars_select(scalar_2_sign_var, endo_base, &endo_base_neg)?;

    MultiScalarMultiplicationCircuit::<F, P>::msm_with_var_scalar_length(
        circuit,
        &[*base, endo_base],
        &[scalar_1, scalar_2],
        128,
    )
}

/// Mapping a point G to phi(G):= lambda G where phi is the endomorphism
fn endomorphism<F, P>(base: &Point<F>) -> Point<F>
where
    F: PrimeField,
    P: TECurveConfig<BaseField = F>,
{
    let x = base.get_x();
    let y = base.get_y();
    let b = F::from_le_bytes_mod_order(COEFF_B.as_ref());
    let c = F::from_le_bytes_mod_order(COEFF_C.as_ref());

    let xy = x * y;
    let y_square = y * y;
    let f_y = c * (F::one() - y_square);
    let g_y = b * (y_square + b);
    let h_y = y_square - b;

    Projective::<P>::new(f_y * h_y, g_y * xy, F::one(), h_y * xy)
        .into_affine()
        .into()
}

/// The circuit for computing the point endomorphism.
fn endomorphism_circuit<F, P>(
    circuit: &mut PlonkCircuit<F>,
    point_var: &PointVariable,
) -> Result<PointVariable, CircuitError>
where
    F: PrimeField,
    P: TECurveConfig<BaseField = F>,
{
    let base = circuit.point_witness(point_var)?;
    let endo_point = endomorphism::<_, P>(&base);
    let endo_point_var = circuit.create_point_variable(endo_point)?;

    let b = F::from_le_bytes_mod_order(COEFF_B.as_ref());
    let c = F::from_le_bytes_mod_order(COEFF_C.as_ref());
    let b_square = b * b;

    let x_var = point_var.get_x();
    let y_var = point_var.get_y();

    // xy = x * y
    let xy_var = circuit.mul(x_var, y_var)?;

    // f(y) = c(1 - y^2)
    let wire = [y_var, y_var, circuit.zero(), circuit.zero()];
    let coeff = [F::zero(), F::zero(), F::zero(), F::zero()];
    let q_mul = [-c, F::zero()];
    let q_c = c;
    let f_y_var = circuit.gen_quad_poly(&wire, &coeff, &q_mul, q_c)?;

    // g(y) = b(y^2 + b)
    let wire = [y_var, y_var, circuit.zero(), circuit.zero()];
    let coeff = [F::zero(), F::zero(), F::zero(), F::zero()];
    let q_mul = [b, F::zero()];
    let q_c = b_square;
    let g_y_var = circuit.gen_quad_poly(&wire, &coeff, &q_mul, q_c)?;

    // h(y) = y^2 - b
    let wire = [y_var, y_var, circuit.zero(), circuit.zero()];
    let coeff = [F::zero(), F::zero(), F::zero(), F::zero()];
    let q_mul = [F::one(), F::zero()];
    let q_c = -b;
    let h_y_var = circuit.gen_quad_poly(&wire, &coeff, &q_mul, q_c)?;

    // res_x = f(y) / (xy)
    circuit.mul_gate(endo_point_var.get_x(), xy_var, f_y_var)?;
    // res_y = g(y) / h(y)
    circuit.mul_gate(endo_point_var.get_y(), h_y_var, g_y_var)?;

    Ok(endo_point_var)
}

/// Decompose a scalar s into k1, k2, s.t.
///     scalar = k1 - k2_sign * k2 * lambda
/// via a Babai's nearest plane algorithm
/// Guarantees that k1 and k2 are less than 128 bits.
fn scalar_decomposition<F: PrimeField>(scalar: &F) -> (F, F, bool) {
    let scalar_z: BigUint = (*scalar).into();

    let tmp = F::from_le_bytes_mod_order(COEFF_N11.as_ref());
    let n11: BigUint = tmp.into();

    let tmp = F::from_le_bytes_mod_order(COEFF_N12.as_ref());
    let n12: BigUint = tmp.into();

    let tmp = F::from_le_bytes_mod_order(COEFF_N21.as_ref());
    let n21: BigUint = tmp.into();

    let tmp = F::from_le_bytes_mod_order(COEFF_N22.as_ref());
    let n22: BigUint = tmp.into();

    let r: BigUint = F::MODULUS.into();
    let r_over_2 = &r / BigUint::from(2u8);

    // beta = vector([n,0]) * self.curve.N_inv
    let beta_1 = &scalar_z * &n11;
    let beta_2 = &scalar_z * &n12;

    let beta_1 = &beta_1 / &r;
    let beta_2 = &beta_2 / &r;

    // b = vector([int(beta[0]), int(beta[1])]) * self.curve.N
    let b1: BigUint = &beta_1 * &n11 + &beta_2 * &n21;
    let b2: BigUint = (&beta_1 * &n12 + &beta_2 * &n22) % r;

    let k1 = F::from(scalar_z - b1);
    let is_k2_pos = b2 < r_over_2;

    let k2 = if is_k2_pos { F::from(b2) } else { -F::from(b2) };

    (k1, k2, is_k2_pos)
}

macro_rules! fq_to_big_int {
    ($fq: expr) => {
        <BigInt as From<BigUint>>::from($fq.into_bigint().into())
    };
}

macro_rules! int_to_fq {
    ($in: expr) => {
        F::from_le_bytes_mod_order(&$in.to_bytes_le().1)
    };
}

// Input a scalar s as in Fq wires,
// compute k1, k2 and a k2_sign s.t.
//  s = k1 - k2_sign * k2 * lambda mod |Fr|
// where
// * s ~ 253 bits, private input
// * lambda ~ 253 bits, public input
// * k1, k2 each ~ 128 bits, private inputs
// * k2_sign - Boolean, private inputs
// Return the variables for k1 and k2
// and sign bit for k2.
#[allow(clippy::type_complexity)]
fn scalar_decomposition_gate<F, P, S>(
    circuit: &mut PlonkCircuit<F>,
    s_var: &Variable,
) -> Result<(Variable, Variable, BoolVar), CircuitError>
where
    F: PrimeField,
    P: TECurveConfig<BaseField = F, ScalarField = S>,
    S: PrimeField,
{
    // the order of scalar field
    // r = 13108968793781547619861935127046491459309155893440570251786403306729687672801 < 2^253
    // q = 52435875175126190479447740508185965837690552500527637822603658699938581184513 < 2^255

    // for an input scalar s,
    // we need to prove the following statement over ZZ
    //
    // (0) lambda * k2_sign * k2 + s = t * Fr::modulus + k1
    //
    // for some t, where
    // * t < (k2 + 1) < 2^128
    // * k1, k2 < sqrt{2r} < 2^128
    // * lambda, s, modulus are ~253 bits
    //
    // which becomes
    // (1) lambda_1 * k2_sign * k2 + 2^128 lambda_2 * k2_sign * k2 + s
    //        - t * r1 - t *2^128 r2 - k1 = 0
    // where
    // (2) lambda = lambda_1 + 2^128 lambda_2   <- public info
    // (3) Fr::modulus = r1 + 2^128 r2          <- public info
    // with
    //  lambda_1 and r1 < 2^128
    //  lambda_2 and r2 < 2^125
    //
    // reorganizing (1) gives us
    // (4)          lambda_1 * k2_sign * k2 + s - t * r1 - k1
    //     + 2^128 (lambda_2 * k2_sign * k2 - t * r2)
    //     = 0
    //
    // Now set
    // (5) tmp = lambda_1 * k2_sign * k2 + s - t * r1 - k1
    // with
    // (6) tmp = tmp1 + 2^128 tmp2
    // for tmp1 < 2^128 and tmp2 < 2^128
    //
    // that is
    // tmp1 will be the lower 128 bits of
    //     lambda * k2_sign * k2 + s - t * Fr::modulus + k1
    // which will be 0 due to (0).
    // (7) tmp1 =  (lambda_1 * k2_sign * k2 + s - t * r1 - k1) % 2^128 = 0
    // note that t * r1 < 2^254
    //
    // i.e. tmp2 will be the carrier overflowing 2^128,
    // and on the 2^128 term, we have
    // (8) tmp2 + lambda_2 * k2_sign * k2 - t * r2 = 0
    // also due to (0).
    //
    // the concrete statements that we need to prove (0) are
    //  (a) k1 < 2^128
    //  (b) k2 < 2^128
    //  (c) tmp1 = 0
    //  (d) tmp2 < 2^128
    //  (e) tmp = tmp1 + 2^128 tmp2
    //  (f) tmp =  lambda_1 * k2_sign * k2 + s - t * r1 - k1
    //  (g) tmp2 + lambda_2 * k2_sign * k2   = t * r2
    // which can all be evaluated over Fq without overflow

    // ============================================
    // step 1: build integers
    // ============================================
    // 2^128
    let two_to_128 = BigInt::from(2u64).pow(128);

    // s
    let s = circuit.witness(*s_var)?;
    let s_int = fq_to_big_int!(s);
    let s_fr = field_switching::<_, S>(&s);

    // lambda = lambda_1 + 2^128 lambda_2
    let lambda = F::from_le_bytes_mod_order(LAMBDA.as_ref());
    let lambda_1 = F::from_le_bytes_mod_order(LAMBDA_1.as_ref());

    let lambda_int = fq_to_big_int!(lambda);
    let lambda_1_int = fq_to_big_int!(lambda_1);
    let lambda_2 = F::from_le_bytes_mod_order(LAMBDA_2.as_ref());

    // s = k1 - lambda * k2 * k2_sign
    let (k1, k2, is_k2_positive) = scalar_decomposition(&s_fr);
    let k1_int = fq_to_big_int!(k1);
    let k2_int = fq_to_big_int!(k2);
    let k2_sign = if is_k2_positive {
        BigInt::from(1)
    } else {
        BigInt::from(-1)
    };
    let k2_with_sign = &k2_int * &k2_sign;

    // fr_order = r1 + 2^128 r2
    let fr_order_uint: BigUint = S::MODULUS.into();
    let fr_order_int: BigInt = fr_order_uint.into();
    let r1 = F::from_le_bytes_mod_order(R1.as_ref());
    let r1_int = fq_to_big_int!(r1);
    let r2 = F::from_le_bytes_mod_order(R2.as_ref());

    // t * t_sign = (lambda * k2 * k2_sign + s - k1) / fr_order
    let mut t_int = (&lambda_int * &k2_with_sign + &s_int - &k1_int) / &fr_order_int;
    let t_int_sign = if t_int < BigInt::zero() {
        t_int = -t_int;
        BigInt::from(-1)
    } else {
        BigInt::from(1)
    };
    let t_int_with_sign = &t_int * &t_int_sign;

    // tmp = tmp1 + 2^128 tmp2 =  lambda_1 * k2 * k2_sign + s - t * t_sign * r1 - k1
    let tmp_int = &lambda_1_int * &k2_with_sign + &s_int - &t_int_with_sign * &r1_int - &k1_int;
    let tmp2_int = &tmp_int / &two_to_128;

    #[cfg(test)]
    {
        use ark_ff::BigInteger;

        let fq_uint: BigUint = F::MODULUS.into();
        let fq_int: BigInt = fq_uint.into();

        let tmp1_int = &tmp_int % &two_to_128;

        let lambda_2_int = fq_to_big_int!(lambda_2);
        let r2_int = fq_to_big_int!(r2);
        // sanity checks
        // equation (0): lambda * k2_sign * k2 + s = t * t_sign * Fr::modulus + k1
        assert_eq!(
            &s_int + &lambda_int * &k2_with_sign,
            &k1_int + &t_int_with_sign * &fr_order_int
        );

        // equation (4)
        //              lambda_1 * k2_sign * k2 + s - t * t_sign * r1 - k1
        //     + 2^128 (lambda_2 * k2_sign * k2 - t * r2)
        //     = 0
        assert_eq!(
            &lambda_1_int * &k2_with_sign + &s_int - &t_int_with_sign * &r1_int - &k1_int
                + &two_to_128 * (&lambda_2_int * &k2_with_sign - &t_int_with_sign * &r2_int),
            BigInt::zero()
        );

        //  (a) k1 < 2^128
        //  (b) k2 < 2^128
        let k1_bits = get_bits(&k1.into_bigint().to_bits_le());
        let k2_bits = get_bits(&k1.into_bigint().to_bits_le());

        assert!(k1_bits < 128, "k1 bits {}", k1_bits);
        assert!(k2_bits < 128, "k2 bits {}", k1_bits);

        //  (c) tmp1 = 0
        //  (d) tmp2 < 2^128
        //  (e) tmp = tmp1 + 2^128 tmp2
        assert!(tmp1_int == BigInt::from(0));
        let tmp2_fq = F::from_le_bytes_mod_order(&tmp2_int.to_bytes_le().1);
        let tmp2_bits = get_bits(&tmp2_fq.into_bigint().to_bits_le());
        assert!(tmp1_int == BigInt::from(0));
        assert!(tmp2_bits < 128, "tmp2 bits {}", tmp2_bits);

        // equation (f): tmp1 + 2^128 tmp2 =  lambda_1 * k2_sign * k2 + s - t * t_sign *
        // r1 - k1
        assert_eq!(
            &tmp1_int + &two_to_128 * &tmp2_int,
            &lambda_1_int * &k2_with_sign + &s_int - &t_int_with_sign * &r1_int - &k1_int
        );
        assert!(&tmp_int + &t_int_with_sign * &r1_int + &k1_int < fq_int);

        assert!(&lambda_1_int * &k2_int + &s_int < fq_int);

        // equation (g) tmp2 + lambda_2 * k2_sign * k2 + s2  = t * t_sign * r2
        assert_eq!(
            &tmp2_int + &lambda_2_int * &k2_with_sign,
            &t_int_with_sign * &r2_int
        );

        // all intermediate data are positive
        assert!(k1_int >= BigInt::zero());
        assert!(k2_int >= BigInt::zero());
        assert!(t_int >= BigInt::zero());
        assert!(tmp_int >= BigInt::zero());
        assert!(tmp2_int >= BigInt::zero());

        // t and k2 has a same sign
        assert_eq!(t_int_sign, k2_sign);
    }

    // ============================================
    // step 2. build the variables
    // ============================================
    let two_to_128 = F::from(BigUint::from(2u64).pow(128));

    let k1_var = circuit.create_variable(int_to_fq!(k1_int))?;
    let k2_var = circuit.create_variable(int_to_fq!(k2_int))?;
    let k2_sign_var = circuit.create_boolean_variable(is_k2_positive)?;

    let t_var = circuit.create_variable(int_to_fq!(t_int))?;

    let tmp_var = circuit.create_variable(int_to_fq!(tmp_int))?;

    let tmp2_var = circuit.create_variable(int_to_fq!(tmp2_int))?;

    // ============================================
    // step 3. range proofs
    // ============================================
    //  (a) k1 < 2^128
    //  (b) k2 < 2^128
    circuit.enforce_in_range(k1_var, 128)?;
    circuit.enforce_in_range(k2_var, 128)?;

    //  (c) tmp1 = 0        <- implied by tmp = 2^128 * tmp2
    //  (d) tmp2 < 2^128
    //  (e) tmp = tmp1 + 2^128 tmp2
    circuit.mul_constant_gate(tmp2_var, two_to_128, tmp_var)?;
    circuit.enforce_in_range(tmp2_var, 128)?;

    // ============================================
    // step 4. equality proofs
    // ============================================
    //  (f) tmp + t * k2_sign * r1 + k1 =  lambda_1 * k2_sign * k2 + s
    //  (note that we cannot do subtraction because subtraction is over Fq)
    let k2_is_pos_sat = {
        //  (f.1) if k2_sign = 1, then, we prove over Z
        //      tmp + t * r1 + k1 =  lambda_1 * k2 + s
        let left_wire = [tmp_var, t_var, k1_var, circuit.zero()];
        let left_coeff = [F::one(), r1, F::one(), F::zero()];
        let left_var = circuit.lc(&left_wire, &left_coeff)?;

        let right_wire = [k2_var, *s_var, circuit.zero(), circuit.zero()];
        let right_coeff = [lambda_1, F::one(), F::zero(), F::zero()];
        let right_var = circuit.lc(&right_wire, &right_coeff)?;

        circuit.is_equal(left_var, right_var)?
    };

    let k2_is_neg_sat = {
        //  (f.2) if k2_sign = -1, then, we prove over Z
        //    lambda_1 * k2 +  tmp + k1 =   s  + t * r1
        let left_wire = [k2_var, tmp_var, k1_var, circuit.zero()];
        let left_coeff = [lambda_1, F::one(), F::one(), F::zero()];
        let left_var = circuit.lc(&left_wire, &left_coeff)?;

        let right_wire = [*s_var, t_var, circuit.zero(), circuit.zero()];
        let right_coeff = [F::one(), r1, F::zero(), F::zero()];
        let right_var = circuit.lc(&right_wire, &right_coeff)?;
        circuit.is_equal(left_var, right_var)?
    };

    //  (f.3) either f.1 or f.2 is satisfied
    let sat =
        circuit.conditional_select(k2_sign_var, k2_is_neg_sat.into(), k2_is_pos_sat.into())?;
    circuit.enforce_true(sat)?;

    //  (g) tmp2 + lambda_2 * k2_sign * k2 + s2  = t * t_sign * r2

    let k2_is_pos_sat = {
        //  (g.1) if k2_sign = 1 then
        //      tmp2 + lambda_2 * k_2_var = t * r2
        let left_wire = [tmp2_var, k2_var, circuit.zero(), circuit.zero()];
        let left_coeff = [F::one(), lambda_2, F::zero(), F::zero()];
        let left_var = circuit.lc(&left_wire, &left_coeff)?;

        let right_var = circuit.mul_constant(t_var, &r2)?;

        circuit.is_equal(left_var, right_var)?
    };

    let k2_is_neg_sat = {
        //  (g.2) if k2_sign = -1 then
        //      tmp2  + t * r2 = lambda_2 * k_2_var
        let left_wire = [tmp2_var, t_var, circuit.zero(), circuit.zero()];
        let left_coeff = [F::one(), r2, F::zero(), F::zero()];
        let left_var = circuit.lc(&left_wire, &left_coeff)?;

        let right_var = circuit.mul_constant(k2_var, &lambda_2)?;

        circuit.is_equal(left_var, right_var)?
    };

    //  (g.3) either g.1 or g.2 is satisfied
    let sat =
        circuit.conditional_select(k2_sign_var, k2_is_neg_sat.into(), k2_is_pos_sat.into())?;
    circuit.enforce_true(sat)?;

    // extract the output
    Ok((k1_var, k2_var, k2_sign_var))
}

#[cfg(test)]
/// return the highest non-zero bits of a bit string.
fn get_bits(a: &[bool]) -> u16 {
    let mut res = 256;
    for e in a.iter().rev() {
        if !e {
            res -= 1;
        } else {
            return res;
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{errors::CircuitError, gadgets::ecc::Point, Circuit, PlonkCircuit};
    use ark_ec::twisted_edwards::{Affine, TECurveConfig as Config};
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsConfig, Fq, Fr};
    use ark_ff::{BigInteger, MontFp, One, PrimeField, UniformRand};
    use jf_utils::{field_switching, fr_to_fq, test_rng};

    #[test]
    fn test_glv() -> Result<(), CircuitError> {
        test_glv_helper::<Fq, EdwardsConfig>()
    }

    fn test_glv_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();

        for _ in 0..100 {
            {
                let mut base = Affine::<P>::rand(&mut rng);
                let s = P::ScalarField::rand(&mut rng);
                let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();

                let s_var = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
                let base_var = circuit.create_point_variable(Point::from(base))?;
                base = (base * s).into();
                let result = circuit.variable_base_scalar_mul::<P>(s_var, &base_var)?;
                assert_eq!(Point::from(base), circuit.point_witness(&result)?);

                // ark_std::println!("Turbo Plonk: {} constraints", circuit.num_gates());
                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            }
            {
                let mut base = Affine::<P>::rand(&mut rng);
                let s = P::ScalarField::rand(&mut rng);
                let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);

                let s_var = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
                let base_var = circuit.create_point_variable(Point::from(base))?;
                base = (base * s).into();
                let result = circuit.variable_base_scalar_mul::<P>(s_var, &base_var)?;
                assert_eq!(Point::from(base), circuit.point_witness(&result)?);

                // ark_std::println!("Ultra Plonk: {} constraints", circuit.num_gates());
                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            }

            {
                let mut base = Affine::<P>::rand(&mut rng);
                let s = P::ScalarField::rand(&mut rng);
                let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();

                let s_var = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
                let base_var = circuit.create_point_variable(Point::from(base))?;
                base = (base * s).into();
                let result = circuit.glv_mul::<P>(s_var, &base_var)?;
                assert_eq!(Point::from(base), circuit.point_witness(&result)?);

                // ark_std::println!("Turbo Plonk GLV: {} constraints", circuit.num_gates());
                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            }

            {
                let mut base = Affine::<P>::rand(&mut rng);
                let s = P::ScalarField::rand(&mut rng);
                let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);

                let s_var = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
                let base_var = circuit.create_point_variable(Point::from(base))?;
                base = (base * s).into();
                let result = circuit.glv_mul::<P>(s_var, &base_var)?;
                assert_eq!(Point::from(base), circuit.point_witness(&result)?);

                // ark_std::println!("Ultra Plonk GLV: {} constraints", circuit.num_gates());
                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn test_endomorphism() {
        let base_point = EdwardsAffine::new_unchecked(
            MontFp!(
                "29627151942733444043031429156003786749302466371339015363120350521834195802525"
            ),
            MontFp!(
                "27488387519748396681411951718153463804682561779047093991696427532072116857978"
            ),
        );
        let endo_point = EdwardsAffine::new_unchecked(
            MontFp!("3995099504672814451457646880854530097687530507181962222512229786736061793535"),
            MontFp!(
                "33370049900732270411777328808452912493896532385897059012214433666611661340894"
            ),
        );
        let base_point: Point<Fq> = base_point.into();
        let endo_point: Point<Fq> = endo_point.into();

        let t = endomorphism::<_, EdwardsConfig>(&base_point);
        assert_eq!(t, endo_point);

        let mut circuit: PlonkCircuit<Fq> = PlonkCircuit::new_turbo_plonk();
        let point_var = circuit.create_point_variable(base_point).unwrap();
        let endo_var = endomorphism_circuit::<_, EdwardsConfig>(&mut circuit, &point_var).unwrap();
        let endo_point_rec = circuit.point_witness(&endo_var).unwrap();
        assert_eq!(endo_point_rec, endo_point);
    }

    #[test]
    fn test_decomposition() {
        let mut rng = test_rng();
        let lambda: Fr = Fr::from_le_bytes_mod_order(LAMBDA.as_ref());

        for _ in 0..100 {
            let scalar = Fr::rand(&mut rng);
            let (k1, k2, is_k2_pos) = scalar_decomposition(&scalar);
            assert!(get_bits(&k1.into_bigint().to_bits_le()) <= 128);
            assert!(get_bits(&k2.into_bigint().to_bits_le()) <= 128);
            let k2 = if is_k2_pos { k2 } else { -k2 };

            assert_eq!(k1 - k2 * lambda, scalar,);

            let mut circuit: PlonkCircuit<Fq> = PlonkCircuit::new_ultra_plonk(16);
            let scalar_var = circuit.create_variable(field_switching(&scalar)).unwrap();
            let (k1_var, k2_var, k2_sign_var) =
                scalar_decomposition_gate::<_, EdwardsConfig, _>(&mut circuit, &scalar_var)
                    .unwrap();

            let k1_rec = circuit.witness(k1_var).unwrap();
            assert_eq!(field_switching::<_, Fq>(&k1), k1_rec);

            let k2_rec = circuit.witness(k2_var).unwrap();
            let k2_sign = circuit.witness(k2_sign_var.into()).unwrap();
            let k2_with_sign_rec = if k2_sign == Fq::one() {
                field_switching::<_, Fr>(&k2_rec)
            } else {
                -field_switching::<_, Fr>(&k2_rec)
            };

            assert_eq!(k2, k2_with_sign_rec);
        }
    }
}
