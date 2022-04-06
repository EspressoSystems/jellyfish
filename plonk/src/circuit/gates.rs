// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementations of various Gates.
use ark_ff::Field;
use ark_std::boxed::Box;
use core::fmt;
use downcast_rs::Downcast;

use crate::constants::{GATE_WIDTH, N_MUL_SELECTORS};

/// Describes a gate with getter for all selectors configuration
pub trait Gate<F: Field>: Downcast + GateClone<F> {
    /// Get the name of a gate.
    fn name(&self) -> &'static str;
    /// Selectors for linear combination.
    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [F::zero(); GATE_WIDTH]
    }
    /// Selectors for Rescue hashes.
    fn q_hash(&self) -> [F; GATE_WIDTH] {
        [F::zero(); GATE_WIDTH]
    }
    /// Selectors for multiplication.
    fn q_mul(&self) -> [F; N_MUL_SELECTORS] {
        [F::zero(); N_MUL_SELECTORS]
    }
    /// The selector for elliptic curve operation.
    fn q_ecc(&self) -> F {
        F::zero()
    }
    /// Constant selector.
    fn q_c(&self) -> F {
        F::zero()
    }
    /// Output wire selector.
    fn q_o(&self) -> F {
        F::zero()
    }
    /// UltraPlonk lookup selector.
    fn q_lookup(&self) -> F {
        F::zero()
    }
    /// UltraPlonk lookup domain separation selector.
    fn q_dom_sep(&self) -> F {
        F::zero()
    }
    /// UltraPlonk table keys.
    fn table_key(&self) -> F {
        F::zero()
    }
    /// UltraPlonk table domain separation ids
    fn table_dom_sep(&self) -> F {
        F::zero()
    }
}
impl_downcast!(Gate<F> where F: Field);

/// Clone a Gate.
pub trait GateClone<F: Field> {
    /// Clone a Gate.
    fn clone_box(&self) -> Box<dyn Gate<F>>;
}

impl<T, F: Field> GateClone<F> for T
where
    T: 'static + Gate<F> + Clone,
{
    fn clone_box(&self) -> Box<dyn Gate<F>> {
        Box::new(self.clone())
    }
}

impl<F: Field> Clone for Box<dyn Gate<F>> {
    fn clone(&self) -> Box<dyn Gate<F>> {
        self.clone_box()
    }
}

impl<F: Field> fmt::Debug for (dyn Gate<F> + 'static) {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: (alex) add more context for debug
        f.write_str(self.name())
    }
}

/// A empty gate for circuit padding
#[derive(Debug, Clone)]
pub struct PaddingGate;

impl<F> Gate<F> for PaddingGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "Padding Gate"
    }
}

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
