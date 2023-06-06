// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of arithmetic gates

use super::Gate;
use crate::constants::{GATE_WIDTH, N_MUL_SELECTORS};
use ark_ff::Field;

/// A constant gate
#[derive(Debug, Clone)]
pub struct ConstantGate<F: Field>(pub(crate) F);

impl<F> Gate<F> for ConstantGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Constant Gate"
    }
    fn q_c(&self) -> F {
        self.0
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// An addition gate
#[derive(Debug, Clone)]
pub struct AdditionGate;

impl<F> Gate<F> for AdditionGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Addition Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [F::one(), F::one(), F::zero(), F::zero()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// Adding a variable by a constant.
#[derive(Debug, Clone)]
pub struct ConstantAdditionGate<F: Field>(pub(crate) F);

impl<F> Gate<F> for ConstantAdditionGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Constant addition Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [F::one(), F::zero(), F::zero(), F::zero()]
    }
    fn q_c(&self) -> F {
        self.0
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A subtraction gate
#[derive(Debug, Clone)]
pub struct SubtractionGate;

impl<F> Gate<F> for SubtractionGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Subtraction Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [F::one(), -F::one(), F::zero(), F::zero()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A multiplication gate
#[derive(Debug, Clone)]
pub struct MultiplicationGate;

impl<F> Gate<F> for MultiplicationGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Multiplication Gate"
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [F::one(), F::zero()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A mul constant gate.
/// Multiply the first variable with the constant.
#[derive(Debug, Clone)]
pub struct ConstantMultiplicationGate<F>(pub(crate) F);

impl<F> Gate<F> for ConstantMultiplicationGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Mul constant Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [self.0, F::zero(), F::zero(), F::zero()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A boolean gate, selectors identical to `MultiplicationGate`, achieve through
/// constraining a * a = a
#[derive(Debug, Clone)]
pub struct BoolGate;

impl<F> Gate<F> for BoolGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Check Boolean Gate"
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        MultiplicationGate.q_mul()
    }
    fn q_o(&self) -> F {
        MultiplicationGate.q_o()
    }
}

/// An equality gate, selectors identical to `SubtractionGate`, achieve through
/// constraining a - b = 0
#[derive(Debug, Clone)]
pub struct EqualityGate;

impl<F> Gate<F> for EqualityGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Check Equality Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        SubtractionGate.q_lc()
    }
    fn q_o(&self) -> F {
        SubtractionGate.q_o()
    }
}

/// An I/O gate for public inputs
#[derive(Debug, Clone)]
pub struct IoGate;

impl<F> Gate<F> for IoGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Public I/O Gate"
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// Gate for checking a value is the fifth root of another
#[derive(Debug, Clone)]
pub struct FifthRootGate;

impl<F: Field> Gate<F> for FifthRootGate {
    fn name(&self) -> &'static str {
        "Raise to the inverse of 5 power Gate"
    }

    fn q_hash(&self) -> [F; GATE_WIDTH] {
        [F::one(), F::zero(), F::zero(), F::zero()]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

/// A deg-2 polynomial gate
#[derive(Clone)]
pub struct QuadPolyGate<F: Field> {
    pub(crate) q_lc: [F; GATE_WIDTH],
    pub(crate) q_mul: [F; N_MUL_SELECTORS],
    pub(crate) q_o: F,
    pub(crate) q_c: F,
}
impl<F> Gate<F> for QuadPolyGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Deg-2 Polynomial Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        self.q_lc
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        self.q_mul
    }
    fn q_o(&self) -> F {
        self.q_o
    }
    fn q_c(&self) -> F {
        self.q_c
    }
}

/// A linear combination gate
#[derive(Clone)]
pub struct LinCombGate<F: Field> {
    pub(crate) coeffs: [F; GATE_WIDTH],
}
impl<F> Gate<F> for LinCombGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Linear Combination Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        self.coeffs
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A multiplication-then-addition gate
#[derive(Clone)]
pub struct MulAddGate<F: Field> {
    pub(crate) coeffs: [F; N_MUL_SELECTORS],
}
impl<F> Gate<F> for MulAddGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Multiplication-then-addition Gate"
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        self.coeffs
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A gate for conditional selection
#[derive(Clone)]
pub struct CondSelectGate;

impl<F> Gate<F> for CondSelectGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Conditional Selection Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [F::zero(), F::one(), F::zero(), F::zero()]
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [-F::one(), F::one()]
    }
    fn q_o(&self) -> F {
        F::one()
    }
}

/// A multiplication-then-addition gate
#[derive(Clone)]
pub struct ArithmeticGate<F: Field> {
    pub(crate) lc_coeffs: [F; GATE_WIDTH],
    pub(crate) mul_coeffs: [F; N_MUL_SELECTORS],
    pub(crate) constant: F,
}
impl<F> Gate<F> for ArithmeticGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Multiplication-then-addition Gate"
    }
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        self.lc_coeffs
    }
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        self.mul_coeffs
    }
    fn q_c(&self) -> F {
        self.constant
    }
    fn q_o(&self) -> F {
        F::one()
    }
}
