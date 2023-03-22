// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Elliptic curve related gates and gadgets. Including both native and
//! non-native fields.

use crate::{errors::CircuitError, gates::*, BoolVar, Circuit, PlonkCircuit, Variable};
use ark_ec::{
    short_weierstrass::{Affine as SWGroupAffine, SWCurveConfig},
    twisted_edwards::{Affine, Projective, TECurveConfig as Config},
    AffineRepr, CurveConfig, CurveGroup, ScalarMul,
};
use ark_ff::PrimeField;
use ark_std::{borrow::ToOwned, boxed::Box, string::ToString, vec, vec::Vec};
use core::marker::PhantomData;

mod conversion;
mod glv;
mod msm;
pub use conversion::*;
pub use msm::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// An elliptic curve point in twisted Edwards affine form (x, y).
pub struct Point<F: PrimeField>(F, F);

impl<F, P> From<Affine<P>> for Point<F>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn from(p: Affine<P>) -> Self {
        if p.is_zero() {
            // separately treat point of infinity since maliciously constructed Affine
            // could be (0,0,true) which is still a valid infinity point but would result in
            // `Point(0, 0)` which might lead to problems as seen in precedence:
            // https://cryptosubtlety.medium.com/00-8d4adcf4d255
            let inf = Affine::<P>::zero();
            Point(inf.x, inf.y)
        } else {
            Point(p.x, p.y)
        }
    }
}

impl<F, P> From<SWGroupAffine<P>> for Point<F>
where
    F: PrimeField,
    P: SWCurveConfig<BaseField = F>,
{
    fn from(p: SWGroupAffine<P>) -> Self {
        if p.is_zero() {
            let inf = SWGroupAffine::<P>::zero();
            Point(inf.x, inf.y)
        } else {
            Point(p.x, p.y)
        }
    }
}

impl<F: PrimeField> Point<F> {
    /// Get the x coordinate of the point.
    pub fn get_x(&self) -> F {
        self.0
    }

    /// Get the y coordinate of the point.
    pub fn get_y(&self) -> F {
        self.1
    }

    /// The inverse point for the edward form.
    pub fn inverse(&self) -> Self {
        Self(-self.0, self.1)
    }
}

impl<F, P> From<Projective<P>> for Point<F>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn from(p: Projective<P>) -> Self {
        let affine_repr = p.into_affine();
        Point(affine_repr.x, affine_repr.y)
    }
}

impl<F, P> From<Point<F>> for Affine<P>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn from(p: Point<F>) -> Self {
        Self::new(p.0, p.1)
    }
}

impl<F, P> From<Point<F>> for Projective<P>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn from(p: Point<F>) -> Self {
        let affine_point: Affine<P> = p.into();
        affine_point.into_group()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Represent variable of an EC point.
pub struct PointVariable(Variable, Variable);

impl PointVariable {
    /// Get the variable representing the x coordinate of the point.
    pub fn get_x(&self) -> Variable {
        self.0
    }

    /// Get the variable representing the y coordinate of the point.
    pub fn get_y(&self) -> Variable {
        self.1
    }
}

// ECC related gates
impl<F: PrimeField> PlonkCircuit<F> {
    /// Return the witness point for the circuit
    pub fn point_witness(&self, point_var: &PointVariable) -> Result<Point<F>, CircuitError> {
        self.check_point_var_bound(point_var)?;
        let x = self.witness(point_var.0)?;
        let y = self.witness(point_var.1)?;
        Ok(Point(x, y))
    }

    /// Add a new EC point (as witness) to the circuit
    pub fn create_point_variable(
        &mut self,
        point: Point<F>,
    ) -> Result<PointVariable, CircuitError> {
        let x_var = self.create_variable(point.0)?;
        let y_var = self.create_variable(point.1)?;
        Ok(PointVariable(x_var, y_var))
    }

    /// Add a new EC point (as a constant) to the circuit
    pub fn create_constant_point_variable(
        &mut self,
        point: Point<F>,
    ) -> Result<PointVariable, CircuitError> {
        let x_var = self.create_constant_variable(point.0)?;
        let y_var = self.create_constant_variable(point.1)?;
        Ok(PointVariable(x_var, y_var))
    }

    /// Add a new EC point (as public input) to the circuit
    pub fn create_public_point_variable(
        &mut self,
        point: Point<F>,
    ) -> Result<PointVariable, CircuitError> {
        let x_var = self.create_public_variable(point.0)?;
        let y_var = self.create_public_variable(point.1)?;
        Ok(PointVariable(x_var, y_var))
    }

    /// Obtain a point variable of the conditional selection from 4 point
    /// candidates, (b0, b1) are two boolean variables indicating the choice
    /// P_b0+2b1 where P0 = (0, 1) the neutral point, P1, P2, P3 are input
    /// parameters.
    /// A bad PointVariable would be returned if (b0, b1) are not boolean
    /// variables, that would ultimately failed to build a correct circuit.
    fn quaternary_point_select<P: Config<BaseField = F>>(
        &mut self,
        b0: BoolVar,
        b1: BoolVar,
        point1: &Point<F>,
        point2: &Point<F>,
        point3: &Point<F>,
    ) -> Result<PointVariable, CircuitError> {
        self.check_var_bound(b0.into())?;
        self.check_var_bound(b1.into())?;

        let selected_point = {
            let selected = match (
                self.witness(b0.into())? == F::one(),
                self.witness(b1.into())? == F::one(),
            ) {
                (false, false) => Point::from(Affine::<P>::zero()),
                (true, false) => point1.to_owned(),
                (false, true) => point2.to_owned(),
                (true, true) => point3.to_owned(),
            };
            // create new point with the same (x, y) coordinates
            self.create_point_variable(selected)?
        };
        let wire_vars_x = [b0.into(), b1.into(), 0, 0, selected_point.0];
        self.insert_gate(
            &wire_vars_x,
            Box::new(QuaternaryPointSelectXGate {
                x1: point1.0,
                x2: point2.0,
                x3: point3.0,
            }),
        )?;
        let wire_vars_y = [b0.into(), b1.into(), 0, 0, selected_point.1];
        self.insert_gate(
            &wire_vars_y,
            Box::new(QuaternaryPointSelectYGate {
                y1: point1.1,
                y2: point2.1,
                y3: point3.1,
            }),
        )?;

        Ok(selected_point)
    }

    /// Obtain a point variable of the conditional selection from 2 point
    /// variables. `b` is a boolean variable that indicates selection of P_b
    /// from (P0, P1).
    /// Return error if invalid input parameters are provided.
    fn binary_point_vars_select(
        &mut self,
        b: BoolVar,
        point0: &PointVariable,
        point1: &PointVariable,
    ) -> Result<PointVariable, CircuitError> {
        self.check_var_bound(b.into())?;
        self.check_point_var_bound(point0)?;
        self.check_point_var_bound(point1)?;

        let selected_x = self.conditional_select(b, point0.0, point1.0)?;
        let selected_y = self.conditional_select(b, point0.1, point1.1)?;
        Ok(PointVariable(selected_x, selected_y))
    }

    /// Constrain two point variables to be the same.
    /// Return error if the input point variables are invalid.
    pub fn enforce_point_equal(
        &mut self,
        point0: &PointVariable,
        point1: &PointVariable,
    ) -> Result<(), CircuitError> {
        self.check_point_var_bound(point0)?;
        self.check_point_var_bound(point1)?;
        self.enforce_equal(point0.0, point1.0)?;
        self.enforce_equal(point0.1, point1.1)?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two point variables are
    /// equal. Return error if point variables are invalid.
    pub fn is_point_equal(
        &mut self,
        point0: &PointVariable,
        point1: &PointVariable,
    ) -> Result<BoolVar, CircuitError> {
        self.check_point_var_bound(point0)?;
        self.check_point_var_bound(point1)?;
        let x_eq = self.is_equal(point0.0, point1.0)?;
        let y_eq = self.is_equal(point0.1, point1.1)?;
        self.logic_and(x_eq, y_eq)
    }
}

impl<F: PrimeField> PlonkCircuit<F> {
    /// Inverse a point variable
    pub fn inverse_point(
        &mut self,
        point_var: &PointVariable,
    ) -> Result<PointVariable, CircuitError> {
        let x_neg = self.sub(self.zero(), point_var.0)?;
        Ok(PointVariable(x_neg, point_var.1))
    }

    /// Return the point variable for the infinity point
    /// in the TE form: (0, 1)
    pub fn neutral_point_variable(&self) -> PointVariable {
        PointVariable(self.zero(), self.one())
    }

    /// Constrain a point variable to be a neutral point (0, 1) if
    /// `expected_neutral` == 1
    /// Constrain a point variable to be NOT a neutral point if
    /// `expected_neutral` == 0
    /// Note that `expected_neutral` is already constrained as a bool variable
    fn neutral_point_gate(
        &mut self,
        point_var: &PointVariable,
        expected_neutral: BoolVar,
    ) -> Result<(), CircuitError> {
        self.check_point_var_bound(point_var)?;
        self.check_var_bound(expected_neutral.into())?;

        // constraint 1: b_x = is_equal(x, 0);
        let b_x = self.is_equal(point_var.0, self.zero())?;
        // constraint 2: b_y = is_equal(y, 1);
        let b_y = self.is_equal(point_var.1, self.one())?;
        // constraint 3: b = b_x * b_y;
        self.mul_gate(b_x.into(), b_y.into(), expected_neutral.into())?;
        Ok(())
    }

    /// Obtain a boolean variable indicating whether a point is the neutral
    /// point (0, 1) Return variable with value 1 if it is, or 0 otherwise
    /// Return error if input variables are invalid
    pub fn is_neutral_point<P>(
        &mut self,
        point_var: &PointVariable,
    ) -> Result<BoolVar, CircuitError>
    where
        P: Config<BaseField = F>,
    {
        self.check_point_var_bound(point_var)?;

        let b = {
            if self.point_witness(point_var)? == Point::from(Affine::<P>::zero()) {
                self.create_boolean_variable(true)?
            } else {
                self.create_boolean_variable(false)?
            }
        };

        self.neutral_point_gate(point_var, b)?;
        Ok(b)
    }
    /// Constrain a point to be on certain curve, namely its coordinates satisfy
    /// the curve equation, which is curve-dependent. Currently we only support
    /// checks of a `Affine::<P>` over a base field which is the bls12-381
    /// scalar field
    ///
    /// Returns error if input variables are invalid
    pub fn enforce_on_curve<P: Config<BaseField = F>>(
        &mut self,
        point_var: &PointVariable,
    ) -> Result<(), CircuitError> {
        self.check_point_var_bound(point_var)?;

        let (x, y) = (point_var.0, point_var.1);
        let wire_vars = [x, x, y, y, 1];
        self.insert_gate(
            &wire_vars,
            Box::new(EdwardsCurveEquationGate::<P> {
                _phantom: PhantomData::default(),
            }),
        )?;
        Ok(())
    }

    /// Constrain variable `point_c` to be the point addition of `point_a` and
    /// `point_b` over an elliptic curve.
    /// Currently only supports Affine::<P> addition.
    ///
    /// Returns error if the input variables are invalid.
    fn ecc_add_gate<P: Config<BaseField = F>>(
        &mut self,
        point_a: &PointVariable,
        point_b: &PointVariable,
        point_c: &PointVariable,
    ) -> Result<(), CircuitError> {
        self.check_point_var_bound(point_a)?;
        self.check_point_var_bound(point_b)?;
        self.check_point_var_bound(point_c)?;

        let (x_1, y_1) = (point_a.0, point_a.1);
        let (x_2, y_2) = (point_b.0, point_b.1);
        let (x_3, y_3) = (point_c.0, point_c.1);

        let x_coordinate_wire_vars = [x_1, y_2, x_2, y_1, x_3];
        self.insert_gate(
            &x_coordinate_wire_vars,
            Box::new(CurvePointXAdditionGate::<P> {
                _phantom: PhantomData::default(),
            }),
        )?;
        let y_coordinate_wire_vars = [x_1, x_2, y_1, y_2, y_3];
        self.insert_gate(
            &y_coordinate_wire_vars,
            Box::new(CurvePointYAdditionGate::<P> {
                _phantom: PhantomData::default(),
            }),
        )?;
        Ok(())
    }

    /// Obtain a variable to the point addition result of `point_a` + `point_b`
    /// where "+" is the group operation over an elliptic curve.
    /// Currently only supports `Affine::<P>` addition.
    ///
    /// Returns error if inputs are invalid
    pub fn ecc_add<P: Config<BaseField = F>>(
        &mut self,
        point_a: &PointVariable,
        point_b: &PointVariable,
    ) -> Result<PointVariable, CircuitError> {
        let (x_1, y_1) = (self.witness(point_a.0)?, self.witness(point_a.1)?);
        let (x_2, y_2) = (self.witness(point_b.0)?, self.witness(point_b.1)?);
        let eq_gate = EdwardsCurveEquationGate::<P> {
            _phantom: PhantomData::default(),
        };
        let d: F = eq_gate.q_ecc();

        let z = d * x_1 * y_1 * x_2 * y_2; // temporary intermediate value
        let x_3 = (x_1 * y_2 + x_2 * y_1) / (F::one() + z);
        let y_3 = (-P::COEFF_A * x_1 * x_2 + y_2 * y_1) / (F::one() - z);
        let point_c = self.create_point_variable(Point(x_3, y_3))?;
        self.ecc_add_gate::<P>(point_a, point_b, &point_c)?;

        Ok(point_c)
    }

    /// Obtain the fixed-based scalar multiplication result of `scalar` * `Base`
    /// Currently only supports `Affine::<P>` scalar multiplication.
    pub fn fixed_base_scalar_mul<P: Config<BaseField = F>>(
        &mut self,
        scalar: Variable,
        base: &Affine<P>,
    ) -> Result<PointVariable, CircuitError> {
        self.check_var_bound(scalar)?;

        let mut num_bits = <P as CurveConfig>::ScalarField::MODULUS_BIT_SIZE as usize;
        // `num_bits` needs to be an even number
        num_bits += num_bits & 1;
        let scalar_bits_le = self.unpack(scalar, num_bits)?;
        let fixed_bases = compute_base_points(&base.into_group(), num_bits / 2)?;
        let mut accum = self.neutral_point_variable();
        for i in 0..num_bits / 2 {
            let b0 = scalar_bits_le.get(2 * i).ok_or_else(|| {
                CircuitError::InternalError(
                    "scalar binary representation has the wrong length".to_string(),
                )
            })?;
            let b1 = scalar_bits_le.get(2 * i + 1).ok_or_else(|| {
                CircuitError::InternalError(
                    "scalar binary representation has the wrong length".to_string(),
                )
            })?;
            let p1 = fixed_bases[0].get(i).ok_or_else(|| {
                CircuitError::InternalError("fixed_bases_1 has the wrong length".to_string())
            })?;
            let p2 = fixed_bases[1].get(i).ok_or_else(|| {
                CircuitError::InternalError("fixed_bases_2 has the wrong length".to_string())
            })?;
            let p3 = fixed_bases[2].get(i).ok_or_else(|| {
                CircuitError::InternalError("fixed_bases_3 has the wrong length".to_string())
            })?;
            let selected = self.quaternary_point_select::<P>(
                *b0,
                *b1,
                &Point::from(*p1),
                &Point::from(*p2),
                &Point::from(*p3),
            )?;
            accum = self.ecc_add::<P>(&accum, &selected)?;
        }
        Ok(accum)
    }

    /// Obtain a variable of the result of a variable base scalar
    /// multiplication. both `scalar` and `base` are variables.
    /// Currently only supports `Affine::<P>`.
    /// If the parameter is bandersnatch, we will use GLV multiplication.
    pub fn variable_base_scalar_mul<P: Config<BaseField = F>>(
        &mut self,
        scalar: Variable,
        base: &PointVariable,
    ) -> Result<PointVariable, CircuitError> {
        self.check_var_bound(scalar)?;
        self.check_point_var_bound(base)?;

        if self.support_lookup()
            && P::ScalarField::MODULUS_BIT_SIZE == 253
            && P::BaseField::MODULUS_BIT_SIZE == 255
        {
            // bandersnatch glv multiplication
            // FIXME: we do not have an easier flag to tell if a parameter
            // is bandersnatch or not, yet.
            self.glv_mul::<P>(scalar, base)
        } else {
            // non-bandersantch multiplication
            msm::MultiScalarMultiplicationCircuit::<F, P>::msm(self, &[*base], &[scalar])
        }
    }

    /// Obtain a variable of the result of a variable base scalar
    /// multiplication. Both `scalar_bits_le` and `base` are variables,
    /// where `scalar_bits_le` is the little-endian form of the scalar.
    /// Currently only supports `Affine::<P>`.
    pub fn variable_base_binary_scalar_mul<P: Config<BaseField = F>>(
        &mut self,
        scalar_bits_le: &[BoolVar],
        base: &PointVariable,
    ) -> Result<PointVariable, CircuitError> {
        for &bit in scalar_bits_le {
            self.check_var_bound(bit.into())?;
        }
        self.check_point_var_bound(base)?;

        let neutral_point_var = self.neutral_point_variable();
        let mut accum = neutral_point_var;
        for i in (0..scalar_bits_le.len()).rev() {
            let z = self.binary_point_vars_select(scalar_bits_le[i], &neutral_point_var, base)?;
            accum = self.ecc_add::<P>(&accum, &accum)?;
            accum = self.ecc_add::<P>(&accum, &z)?;
        }
        Ok(accum)
    }
}

// private helper functions
impl<F: PrimeField> PlonkCircuit<F> {
    fn check_point_var_bound(&self, point_var: &PointVariable) -> Result<(), CircuitError> {
        self.check_var_bound(point_var.0)?;
        self.check_var_bound(point_var.1)?;
        Ok(())
    }
}

// Given a base point [G] and a scalar s of length 2*n, denote as s[G] the
// scalar multiplication.
// The function computes:
// {4^i * [G]}_{i=0..n-1}, {2 * 4^i * [G]}_{i=0..n-1}, and {3 * 4^i *
// [G]}_{i=0..n-1}
// TODO (tessico): this used to operate on Affine points, but now it takes in
// Projective points. There are some known issues with outputting projectives,
// we should make sure that the usage here is safe.
fn compute_base_points<E: ScalarMul>(base: &E, len: usize) -> Result<[Vec<E>; 3], CircuitError> {
    if len == 0 {
        return Err(CircuitError::InternalError(
            "compute base points length input parameter must be positive".to_string(),
        ));
    }
    fn next_base<E: ScalarMul>(bases: &[E]) -> Result<E, CircuitError> {
        let last = *bases.last().ok_or_else(|| {
            CircuitError::InternalError(
                "Initialize the fixed base vector before calling this function".to_string(),
            )
        })?;
        Ok(last.double().double())
    }
    fn fill_bases<E: ScalarMul>(bases: &mut Vec<E>, len: usize) -> Result<(), CircuitError> {
        for _ in 1..len {
            bases.push(next_base(bases)?);
        }
        Ok(())
    }

    let mut b = *base;
    // base1 = (B, 4*B, ..., 4^(l-1)*B)
    let mut bases1 = vec![b];
    b = b.double();
    // base2 = (2*B, 2*4*B, ..., 2*4^(l-1)*B)
    let mut bases2 = vec![b];
    b += base;
    // base3 = (3*B, 3*4*B, ..., 3*4^(l-1)*B)
    let mut bases3 = vec![b];

    #[cfg(feature = "parallel")]
    {
        rayon::join(
            || {
                rayon::join(
                    || fill_bases(&mut bases1, len).ok(),
                    || fill_bases(&mut bases2, len).ok(),
                )
            },
            || fill_bases(&mut bases3, len).ok(),
        );
    }

    #[cfg(not(feature = "parallel"))]
    {
        fill_bases(&mut bases1, len).ok();
        fill_bases(&mut bases2, len).ok();
        fill_bases(&mut bases3, len).ok();
    }

    // converting Affine -> Points here.
    // Cannot do it earlier: in `fill_bases` we need to do `double`
    // todo(ZZ): consider removing `Point<T>` completely and directly use
    // `Affine<P>` let bases1 =
    // bases1.iter().map(|e|Point::<F>::from(*e)).collect(); let bases2 =
    // bases2.iter().map(|e|Point::<F>::from(*e)).collect(); let bases3 =
    // bases3.iter().map(|e|Point::<F>::from(*e)).collect();

    Ok([bases1, bases2, bases3])
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{gadgets::test_utils::test_variable_independence_for_circuit, Circuit};
    use ark_bls12_377::{g1::Config as Param761, Fq as Fq377};
    use ark_ec::{twisted_edwards::TECurveConfig as Config, Group};
    use ark_ed_on_bls12_377::{EdwardsConfig as Param377, Fq as FqEd377};
    use ark_ed_on_bls12_381::{EdwardsConfig as Param381, Fq as FqEd381};
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsConfig as Param381b, Fq as FqEd381b};
    use ark_ed_on_bn254::{EdwardsConfig as Param254, Fq as FqEd354};
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::str::FromStr;
    use jf_utils::fr_to_fq;

    #[test]
    fn test_is_neutral() -> Result<(), CircuitError> {
        test_is_neutral_helper::<FqEd354, Param254>()?;
        test_is_neutral_helper::<FqEd377, Param377>()?;
        test_is_neutral_helper::<FqEd381, Param381>()?;
        test_is_neutral_helper::<FqEd381b, Param381b>()?;
        test_is_neutral_helper::<Fq377, Param761>()
    }

    fn test_is_neutral_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField + ?Sized,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p1 = circuit.create_point_variable(Point(F::zero(), F::one()))?;
        let p2 = circuit.create_point_variable(Point(F::from(2353u32), F::one()))?;
        let p1_check = circuit.is_neutral_point::<P>(&p1)?;
        let p2_check = circuit.is_neutral_point::<P>(&p2)?;

        assert_eq!(circuit.witness(p1_check.into())?, F::one());
        assert_eq!(circuit.witness(p2_check.into())?, F::zero());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(p1.0) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .is_neutral_point::<P>(&PointVariable(circuit.num_vars(), circuit.num_vars() - 1))
            .is_err());

        let circuit_1 = build_is_neutral_circuit::<F, P>(Point(F::zero(), F::one()))?;
        let circuit_2 = build_is_neutral_circuit::<F, P>(Point(F::one(), F::zero()))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_is_neutral_circuit<F, P>(point: Point<F>) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p = circuit.create_point_variable(point)?;
        circuit.is_neutral_point::<P>(&p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    macro_rules! test_enforce_on_curve {
        ($fq:tt, $param:tt, $pt:tt) => {
            let mut circuit: PlonkCircuit<$fq> = PlonkCircuit::new_turbo_plonk();
            let p1 = circuit.create_point_variable(Point($fq::zero(), $fq::one()))?;
            circuit.enforce_on_curve::<$param>(&p1)?;
            let p2 = circuit.create_point_variable($pt)?;
            circuit.enforce_on_curve::<$param>(&p2)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            let p3 = circuit.create_point_variable(Point($fq::one(), $fq::one()))?;
            circuit.enforce_on_curve::<$param>(&p3)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            // Check variable out of bound error.
            assert!(circuit
                .enforce_on_curve::<$param>(&PointVariable(
                    circuit.num_vars(),
                    circuit.num_vars() - 1
                ))
                .is_err());

            let circuit_1 =
                build_enforce_on_curve_circuit::<_, $param>(Point($fq::zero(), $fq::one()))?;
            let circuit_2 = build_enforce_on_curve_circuit::<_, $param>(Point(
                $fq::from(5u32),
                $fq::from(89u32),
            ))?;
            test_variable_independence_for_circuit(circuit_1, circuit_2)?;
        };
    }

    #[test]
    fn test_enforce_on_curve() -> Result<(), CircuitError> {
        // generator for ed_on_bn254 curve
        let ed_on_254_gen = Point(
            FqEd354::from_str(
                "19698561148652590122159747500897617769866003486955115824547446575314762165298",
            )
            .unwrap(),
            FqEd354::from_str(
                "19298250018296453272277890825869354524455968081175474282777126169995084727839",
            )
            .unwrap(),
        );
        // generator for ed_on_bls377 curve
        let ed_on_377_gen = Point(
            FqEd377::from_str(
                "4497879464030519973909970603271755437257548612157028181994697785683032656389",
            )
            .unwrap(),
            FqEd377::from_str(
                "4357141146396347889246900916607623952598927460421559113092863576544024487809",
            )
            .unwrap(),
        );
        // generator for ed_on_bls381 curve
        let ed_on_381_gen = Point(
            FqEd381::from_str(
                "8076246640662884909881801758704306714034609987455869804520522091855516602923",
            )
            .unwrap(),
            FqEd381::from_str(
                "13262374693698910701929044844600465831413122818447359594527400194675274060458",
            )
            .unwrap(),
        );
        // generator for ed_on_bls381_bandersnatch curve
        let ed_on_381b_gen = Point(
            FqEd381::from_str(
                "18886178867200960497001835917649091219057080094937609519140440539760939937304",
            )
            .unwrap(),
            FqEd381::from_str(
                "19188667384257783945677642223292697773471335439753913231509108946878080696678",
            )
            .unwrap(),
        );
        // generator for bls377 G1 curve
        let bls377_gen = Point(
            Fq377::from_str(
                "71222569531709137229370268896323705690285216175189308202338047559628438110820800641278662592954630774340654489393",
            )
            .unwrap(),
            Fq377::from_str(
                "6177051365529633638563236407038680211609544222665285371549726196884440490905471891908272386851767077598415378235",
            )
            .unwrap(),
        );

        test_enforce_on_curve!(FqEd354, Param254, ed_on_254_gen);
        test_enforce_on_curve!(FqEd377, Param377, ed_on_377_gen);
        test_enforce_on_curve!(FqEd381, Param381, ed_on_381_gen);
        test_enforce_on_curve!(FqEd381b, Param381b, ed_on_381b_gen);
        test_enforce_on_curve!(Fq377, Param761, bls377_gen);
        Ok(())
    }

    fn build_enforce_on_curve_circuit<F, P>(
        point: Point<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p = circuit.create_point_variable(point)?;
        circuit.enforce_on_curve::<P>(&p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_curve_point_addition() -> Result<(), CircuitError> {
        test_curve_point_addition_helper::<FqEd354, Param254>()?;
        test_curve_point_addition_helper::<FqEd377, Param377>()?;
        test_curve_point_addition_helper::<FqEd381, Param381>()?;
        test_curve_point_addition_helper::<FqEd381b, Param381b>()?;
        test_curve_point_addition_helper::<Fq377, Param761>()
    }

    fn test_curve_point_addition_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let p1 = Affine::<P>::rand(&mut rng);
        let p2 = Affine::<P>::rand(&mut rng);
        let p3 = (p1 + p2).into_affine();

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p1_var = circuit.create_point_variable(Point::from(p1))?;
        let p2_var = circuit.create_point_variable(Point::from(p2))?;
        let p3_var = circuit.ecc_add::<P>(&p1_var, &p2_var)?;

        assert_eq!(circuit.witness(p3_var.0)?, p3.x);
        assert_eq!(circuit.witness(p3_var.1)?, p3.y);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(p3_var.0) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .ecc_add::<P>(&PointVariable(0, 0), &PointVariable(1, circuit.num_vars()))
            .is_err());

        let p1 = Affine::<P>::rand(&mut rng);
        let p2 = Affine::<P>::rand(&mut rng);
        let p3 = Affine::<P>::rand(&mut rng);
        let p4 = Affine::<P>::rand(&mut rng);
        let circuit_1 =
            build_curve_point_addition_circuit::<F, P>(Point::from(p1), Point::from(p2))?;
        let circuit_2 =
            build_curve_point_addition_circuit::<F, P>(Point::from(p3), Point::from(p4))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_curve_point_addition_circuit<F, P>(
        p1: Point<F>,
        p2: Point<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p1_var = circuit.create_point_variable(p1)?;
        let p2_var = circuit.create_point_variable(p2)?;
        circuit.ecc_add::<P>(&p1_var, &p2_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_quaternary_point_select() -> Result<(), CircuitError> {
        test_quaternary_point_select_helper::<FqEd354, Param254>()?;
        test_quaternary_point_select_helper::<FqEd377, Param377>()?;
        test_quaternary_point_select_helper::<FqEd381, Param381>()?;
        test_quaternary_point_select_helper::<FqEd381b, Param381b>()?;
        test_quaternary_point_select_helper::<Fq377, Param761>()
    }

    fn test_quaternary_point_select_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let p1 = Affine::<P>::rand(&mut rng);
        let p2 = Affine::<P>::rand(&mut rng);
        let p3 = Affine::<P>::rand(&mut rng);

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let false_var = circuit.false_var();
        let true_var = circuit.true_var();

        let select_p0 = circuit.quaternary_point_select::<P>(
            false_var,
            false_var,
            &Point::from(p1),
            &Point::from(p2),
            &Point::from(p3),
        )?;
        assert_eq!(
            Point(F::zero(), F::one()),
            Point(circuit.witness(select_p0.0)?, circuit.witness(select_p0.1)?)
        );
        let select_p1 = circuit.quaternary_point_select::<P>(
            true_var,
            false_var,
            &Point::from(p1),
            &Point::from(p2),
            &Point::from(p3),
        )?;
        assert_eq!(Point::from(p1), circuit.point_witness(&select_p1)?);
        let select_p2 = circuit.quaternary_point_select::<P>(
            false_var,
            true_var,
            &Point::from(p1),
            &Point::from(p2),
            &Point::from(p3),
        )?;
        assert_eq!(Point::from(p2), circuit.point_witness(&select_p2)?);
        let select_p3 = circuit.quaternary_point_select::<P>(
            true_var,
            true_var,
            &Point::from(p1),
            &Point::from(p2),
            &Point::from(p3),
        )?;
        assert_eq!(Point::from(p3), circuit.point_witness(&select_p3)?);

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        *circuit.witness_mut(select_p3.0) = p2.x;
        *circuit.witness_mut(select_p3.1) = p2.y;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        let circuit_1 = build_quaternary_select_gate::<F, P>(false, false)?;
        let circuit_2 = build_quaternary_select_gate::<F, P>(true, true)?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;
        Ok(())
    }

    fn build_quaternary_select_gate<F, P>(
        b0: bool,
        b1: bool,
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let b0_var = circuit.create_boolean_variable(b0)?;
        let b1_var = circuit.create_boolean_variable(b1)?;

        let mut rng = jf_utils::test_rng();
        let p1 = Affine::<P>::rand(&mut rng);
        let p2 = Affine::<P>::rand(&mut rng);
        let p3 = Affine::<P>::rand(&mut rng);
        circuit.quaternary_point_select::<P>(
            b0_var,
            b1_var,
            &Point::from(p1),
            &Point::from(p2),
            &Point::from(p3),
        )?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_point_equal_gate() -> Result<(), CircuitError> {
        test_point_equal_gate_helper::<FqEd354, Param254>()?;
        test_point_equal_gate_helper::<FqEd377, Param377>()?;
        test_point_equal_gate_helper::<FqEd381, Param381>()?;
        test_point_equal_gate_helper::<FqEd381b, Param381b>()?;
        test_point_equal_gate_helper::<Fq377, Param761>()
    }

    fn test_point_equal_gate_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let p = Affine::<P>::rand(&mut rng);

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let p1_var = circuit.create_point_variable(Point::from(p))?;
        let p2_var = circuit.create_point_variable(Point::from(p))?;
        circuit.enforce_point_equal(&p1_var, &p2_var)?;

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(p2_var.0) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .enforce_point_equal(&PointVariable(0, 0), &PointVariable(1, circuit.num_vars()))
            .is_err());

        let new_p = Affine::<P>::rand(&mut rng);
        let circuit_1 = build_point_equal_circuit(Point::from(p), Point::from(p))?;
        let circuit_2 = build_point_equal_circuit(Point::from(new_p), Point::from(new_p))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_point_equal_circuit<F: PrimeField>(
        p1: Point<F>,
        p2: Point<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p1_var = circuit.create_point_variable(p1)?;
        let p2_var = circuit.create_point_variable(p2)?;
        circuit.enforce_point_equal(&p1_var, &p2_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_is_equal_point() -> Result<(), CircuitError> {
        test_is_equal_point_helper::<FqEd354, Param254>()?;
        test_is_equal_point_helper::<FqEd377, Param377>()?;
        test_is_equal_point_helper::<FqEd381, Param381>()?;
        test_is_equal_point_helper::<FqEd381b, Param381b>()?;
        test_is_equal_point_helper::<Fq377, Param761>()
    }

    fn test_is_equal_point_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let p1 = Affine::<P>::rand(&mut rng);
        let p2 = p1;
        let p3 = Affine::<P>::rand(&mut rng);

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p1_var = circuit.create_point_variable(Point::from(p1))?;
        let p2_var = circuit.create_point_variable(Point::from(p2))?;
        let p3_var = circuit.create_point_variable(Point::from(p3))?;
        let p1_p2_eq = circuit.is_point_equal(&p1_var, &p2_var)?;
        let p1_p3_eq = circuit.is_point_equal(&p1_var, &p3_var)?;

        assert_eq!(circuit.witness(p1_p2_eq.into())?, F::one());
        assert_eq!(circuit.witness(p1_p3_eq.into())?, F::zero());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(p2_var.0) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .is_point_equal(&PointVariable(0, 0), &PointVariable(1, circuit.num_vars()))
            .is_err());

        let circuit_1 =
            build_is_equal_point_circuit(Point::from(p1), Point::from(p2), Point::from(p3))?;
        let circuit_2 =
            build_is_equal_point_circuit(Point::from(p3), Point::from(p3), Point::from(p1))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_is_equal_point_circuit<F: PrimeField>(
        p1: Point<F>,
        p2: Point<F>,
        p3: Point<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let p1_var = circuit.create_point_variable(p1)?;
        let p2_var = circuit.create_point_variable(p2)?;
        let p3_var = circuit.create_point_variable(p3)?;
        circuit.is_point_equal(&p1_var, &p2_var)?;
        circuit.is_point_equal(&p1_var, &p3_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_compute_fixed_bases() -> Result<(), CircuitError> {
        test_compute_fixed_bases_helper::<FqEd354, Param254>()?;
        test_compute_fixed_bases_helper::<FqEd377, Param377>()?;
        test_compute_fixed_bases_helper::<FqEd381, Param381>()?;
        test_compute_fixed_bases_helper::<FqEd381b, Param381b>()?;
        test_compute_fixed_bases_helper::<Fq377, Param761>()
    }

    fn test_compute_fixed_bases_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        fn check_base_list<F, P>(bases: &[Projective<P>])
        where
            F: PrimeField,
            P: Config<BaseField = F>,
        {
            bases
                .windows(2)
                .for_each(|neighbors| assert!(neighbors[1] == neighbors[0].double().double()));
        }

        let mut rng = jf_utils::test_rng();

        let base = Affine::<P>::rand(&mut rng);
        let base2 = base.into_group().double();
        let base3 = base + base2;

        assert_eq!(
            compute_base_points(&base.into_group(), 1)?,
            [vec![base.into_group()], vec![base2], vec![base3]]
        );
        let size = 10;
        let result = compute_base_points(&base.into_group(), size)?;
        let bases1 = &result[0];
        assert_eq!(bases1.len(), size);
        let bases2 = &result[1];
        assert_eq!(bases2.len(), size);
        let bases3 = &result[2];
        assert_eq!(bases3.len(), size);
        check_base_list(bases1);
        check_base_list(bases2);
        check_base_list(bases3);
        bases1
            .iter()
            .zip(bases2.iter())
            .zip(bases3.iter())
            .for_each(|((&b1, &b2), &b3)| {
                assert!(b2 == b1.double());
                assert!(b3 == b1 + b2);
            });

        Ok(())
    }

    #[test]
    fn test_fixed_based_scalar_mul() -> Result<(), CircuitError> {
        test_fixed_based_scalar_mul_helper::<FqEd354, Param254>()?;
        test_fixed_based_scalar_mul_helper::<FqEd377, Param377>()?;
        test_fixed_based_scalar_mul_helper::<FqEd381, Param381>()?;
        test_fixed_based_scalar_mul_helper::<FqEd381b, Param381b>()?;
        test_fixed_based_scalar_mul_helper::<Fq377, Param761>()
    }

    fn test_fixed_based_scalar_mul_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();

        for _ in 0..6 {
            let mut base = Affine::<P>::rand(&mut rng);
            let s = P::ScalarField::rand(&mut rng);
            let scalar = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
            let result = circuit.fixed_base_scalar_mul(scalar, &base)?;
            base = (base * s).into();
            assert_eq!(Point::from(base), circuit.point_witness(&result)?);
        }
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // wrong witness should fail
        *circuit.witness_mut(2) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .fixed_base_scalar_mul(circuit.num_vars(), &Affine::<P>::rand(&mut rng))
            .is_err());

        let circuit_1 = build_fixed_based_scalar_mul_circuit::<F, P>(F::from(87u32))?;
        let circuit_2 = build_fixed_based_scalar_mul_circuit::<F, P>(F::from(2u32))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;
        Ok(())
    }

    fn build_fixed_based_scalar_mul_circuit<F, P>(
        scalar: F,
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let base = Affine::<P>::rand(&mut rng);
        let scalar_var = circuit.create_variable(scalar)?;
        circuit.fixed_base_scalar_mul(scalar_var, &base)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_binary_point_vars_select() -> Result<(), CircuitError> {
        test_binary_point_vars_select_helper::<FqEd354, Param254>()?;
        test_binary_point_vars_select_helper::<FqEd377, Param377>()?;
        test_binary_point_vars_select_helper::<FqEd381, Param381>()?;
        test_binary_point_vars_select_helper::<FqEd381b, Param381b>()?;
        test_binary_point_vars_select_helper::<Fq377, Param761>()
    }
    fn test_binary_point_vars_select_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let p0 = Affine::<P>::rand(&mut rng);
        let p1 = Affine::<P>::rand(&mut rng);
        let p2 = Affine::<P>::rand(&mut rng);

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let p0_var = circuit.create_point_variable(Point::from(p0))?;
        let p1_var = circuit.create_point_variable(Point::from(p1))?;
        let true_var = circuit.true_var();
        let false_var = circuit.false_var();

        let select_p0 = circuit.binary_point_vars_select(false_var, &p0_var, &p1_var)?;
        assert_eq!(circuit.point_witness(&select_p0)?, Point::from(p0));
        let select_p1 = circuit.binary_point_vars_select(true_var, &p0_var, &p1_var)?;
        assert_eq!(circuit.point_witness(&select_p1)?, Point::from(p1));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // wrong witness should fail
        *circuit.witness_mut(p1_var.0) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        assert!(circuit
            .binary_point_vars_select(
                false_var,
                &p0_var,
                &PointVariable(p1_var.0, circuit.num_vars()),
            )
            .is_err());

        let circuit_1 =
            build_binary_point_vars_select_circuit::<F, P>(true, Point::from(p0), Point::from(p1))?;
        let circuit_2 = build_binary_point_vars_select_circuit::<F, P>(
            false,
            Point::from(p1),
            Point::from(p2),
        )?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_binary_point_vars_select_circuit<F, P>(
        b: bool,
        p0: Point<F>,
        p1: Point<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let b_var = circuit.create_boolean_variable(b)?;
        let p0_var = circuit.create_point_variable(p0)?;
        let p1_var = circuit.create_point_variable(p1)?;
        circuit.binary_point_vars_select(b_var, &p0_var, &p1_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_variable_base_scalar_mul() -> Result<(), CircuitError> {
        test_variable_base_scalar_mul_helper::<FqEd354, Param254>()?;
        test_variable_base_scalar_mul_helper::<FqEd377, Param377>()?;
        test_variable_base_scalar_mul_helper::<FqEd381, Param381>()?;
        test_variable_base_scalar_mul_helper::<FqEd381b, Param381b>()?;
        test_variable_base_scalar_mul_helper::<Fq377, Param761>()
    }
    fn test_variable_base_scalar_mul_helper<F, P>() -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();

        for _ in 0..6 {
            let mut base = Affine::<P>::rand(&mut rng);
            let s = P::ScalarField::rand(&mut rng);
            let s_var = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
            let base_var = circuit.create_point_variable(Point::from(base))?;
            base = (base * s).into();
            let result = circuit.variable_base_scalar_mul::<P>(s_var, &base_var)?;
            assert_eq!(Point::from(base), circuit.point_witness(&result)?);
        }
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        let base = Affine::<P>::rand(&mut rng);
        let s = P::ScalarField::rand(&mut rng);
        let s_var = circuit.create_variable(fr_to_fq::<F, P>(&s))?;
        let base_var = circuit.create_point_variable(Point::from(base))?;
        // wrong witness should fail
        *circuit.witness_mut(2) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .variable_base_scalar_mul::<P>(circuit.num_vars(), &base_var)
            .is_err());
        assert!(circuit
            .variable_base_scalar_mul::<P>(
                s_var,
                &PointVariable(circuit.num_vars(), circuit.num_vars())
            )
            .is_err());

        let circuit_1 =
            build_variable_base_scalar_mul_circuit::<F, P>(F::zero(), Point::from(base))?;
        let circuit_2 = build_variable_base_scalar_mul_circuit::<F, P>(
            F::from(314u32),
            Point::from(Affine::<P>::rand(&mut rng)),
        )?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_variable_base_scalar_mul_circuit<F, P>(
        scalar: F,
        base: Point<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let scalar_var = circuit.create_variable(scalar)?;
        let base_var = circuit.create_point_variable(base)?;
        circuit.variable_base_scalar_mul::<P>(scalar_var, &base_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }
}
