// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of ECC related gates

use core::marker::PhantomData;

use crate::{
    constants::{GATE_WIDTH, N_MUL_SELECTORS},
    gates::Gate,
};
use ark_ec::twisted_edwards::TECurveConfig as Config;
use ark_ff::PrimeField;
use derivative::Derivative;

#[inline]
fn edwards_coeff_d<P: Config>() -> P::BaseField {
    P::COEFF_D
}

/// A gate for checking a point conforming the twisted Edwards curve equation
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct EdwardsCurveEquationGate<P: Config> {
    pub(crate) _phantom: PhantomData<P>,
}

impl<F, P> Gate<F> for EdwardsCurveEquationGate<P>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn name(&self) -> &'static str {
        "Curve Equation Gate"
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        // edwards equation: ax^2 + y^2 =1 + dx^2y^2
        // for ed_on_bn curves, we have a = 1
        // for ed_on_bls curves, we have a = -1
        [-P::COEFF_A, -F::one()]
    }
    fn q_c(&self) -> F {
        F::one()
    }
    fn q_ecc(&self) -> F {
        edwards_coeff_d::<P>()
    }
}

/// A gate for point addition on x-coordinate between two Curve Points
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct CurvePointXAdditionGate<P: Config> {
    pub(crate) _phantom: PhantomData<P>,
}

impl<F, P> Gate<F> for CurvePointXAdditionGate<P>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn name(&self) -> &'static str {
        "Point Addition X-coordinate Gate"
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [F::one(), F::one()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
    fn q_ecc(&self) -> F {
        let d: F = edwards_coeff_d::<P>();
        -d
    }
}

/// A gate for point addition on y-coordinate between two Curve Points
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct CurvePointYAdditionGate<P: Config> {
    pub(crate) _phantom: PhantomData<P>,
}

impl<F, P> Gate<F> for CurvePointYAdditionGate<P>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn name(&self) -> &'static str {
        "Point Addition Y-coordinate Gate"
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [-P::COEFF_A, F::one()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
    fn q_ecc(&self) -> F {
        edwards_coeff_d::<P>()
    }
}

/// A point selection gate on x-coordinate for conditional selection among 4
/// point candidates
/// P0 is default neutral point, P1, P2, P3 are public constants
#[derive(Clone)]
pub struct QuaternaryPointSelectXGate<F: PrimeField> {
    pub(crate) x1: F,
    pub(crate) x2: F,
    pub(crate) x3: F,
}

impl<F> Gate<F> for QuaternaryPointSelectXGate<F>
where
    F: PrimeField,
{
    fn name(&self) -> &'static str {
        "4-ary Point Selection X-coordinate Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [self.x1, self.x2, F::zero(), F::zero()]
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [self.x3 - self.x2 - self.x1, F::zero()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A point selection gate on y-coordinate for conditional selection among 4
/// point candidates
/// P0 is default neutral point, P1, P2, P3 are public constants
#[derive(Clone)]
pub struct QuaternaryPointSelectYGate<F: PrimeField> {
    pub(crate) y1: F,
    pub(crate) y2: F,
    pub(crate) y3: F,
}

impl<F> Gate<F> for QuaternaryPointSelectYGate<F>
where
    F: PrimeField,
{
    fn name(&self) -> &'static str {
        "4-ary Point Selection Y-coordinate Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [self.y1 - F::one(), self.y2 - F::one(), F::zero(), F::zero()]
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [self.y3 - self.y2 - self.y1 + F::one(), F::zero()]
    }
    fn q_c(&self) -> F {
        F::one()
    }
    fn q_o(&self) -> F {
        F::one()
    }
}
