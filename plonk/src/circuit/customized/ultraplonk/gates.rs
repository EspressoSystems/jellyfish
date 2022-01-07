use crate::circuit::gates::Gate;
use ark_ff::Field;

/// An UltraPlonk lookup gate
#[derive(Debug, Clone)]
pub struct LookupGate;

impl<F> Gate<F> for LookupGate
where
    F: Field,
{
    fn name(&self) -> &'static str {
        "UltraPlonk Lookup Gate"
    }
    fn q_lookup(&self) -> F {
        F::one()
    }
}
