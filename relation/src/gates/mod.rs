// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for various circuit gates.
use ark_ff::Field;
use ark_std::boxed::Box;
use core::fmt;
use downcast_rs::{impl_downcast, Downcast};
use dyn_clone::DynClone;

use crate::constants::{GATE_WIDTH, N_MUL_SELECTORS};

mod arithmetic;
mod ecc;
mod logic;
mod lookup;

pub use arithmetic::*;
pub use ecc::*;
pub use logic::*;
pub use lookup::*;

/// Describes a gate with getter for all selectors configuration
pub trait Gate<F: Field>: Downcast + DynClone {
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

impl<F: Field> Clone for Box<dyn Gate<F>> {
    fn clone(&self) -> Box<dyn Gate<F>> {
        dyn_clone::clone_box(&**self)
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
