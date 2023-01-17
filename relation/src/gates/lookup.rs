// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of UltraPlonk lookup gates

use super::Gate;
use ark_ff::Field;

/// An UltraPlonk lookup gate
#[derive(Debug, Clone)]
pub struct LookupGate<F: Field> {
    pub(crate) q_dom_sep: F,
    pub(crate) table_dom_sep: F,
    pub(crate) table_key: F,
}

impl<F> Gate<F> for LookupGate<F>
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "UltraPlonk Lookup Gate"
    }
    fn q_lookup(&self) -> F {
        F::one()
    }
    fn q_dom_sep(&self) -> F {
        self.q_dom_sep
    }
    fn table_key(&self) -> F {
        self.table_key
    }
    fn table_dom_sep(&self) -> F {
        self.table_dom_sep
    }
}
