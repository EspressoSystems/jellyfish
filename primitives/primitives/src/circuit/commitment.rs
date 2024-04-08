// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of the commitment scheme.

use crate::{
    rescue::{RescueParameter, CRHF_RATE},
    utils::pad_with,
};
use ark_std::vec;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit, Variable};

use super::rescue::RescueNativeGadget;

/// Circuit implementation of the commitment scheme.
pub trait CommitmentGadget {
    // Commitment scheme
    /// Commitment function.
    /// * `input` - input variables,
    /// * `blinding` - blinding variable
    /// * `returns` a variable that refers to the commitment value
    /// The underlying the commitment instance is bound to a specific length.
    /// Hence input length must match it.
    fn commit(&mut self, input: &[Variable], blinding: Variable) -> Result<Variable, CircuitError>;
}

impl<F> CommitmentGadget for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn commit(&mut self, input: &[Variable], blinding: Variable) -> Result<Variable, CircuitError> {
        let mut msg = vec![blinding];
        msg.extend_from_slice(input);
        pad_with(&mut msg, CRHF_RATE, self.zero());
        Ok(RescueNativeGadget::<F>::rescue_sponge_no_padding(self, &msg, 1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::commitment::CommitmentGadget,
        commitment::{CommitmentScheme, FixedLengthRescueCommitment},
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::UniformRand;
    use ark_std::vec::Vec;
    use itertools::Itertools;
    use jf_relation::{Circuit, PlonkCircuit, Variable};

    const TEST_INPUT_LEN: usize = 10;
    const TEST_INPUT_LEN_PLUS_ONE: usize = 10 + 1;

    macro_rules! test_commit_circuit {
        ($base_field:tt) => {
            let mut circuit: PlonkCircuit<$base_field> = PlonkCircuit::new_turbo_plonk();
            let mut prng = jf_utils::test_rng();

            let blinding = $base_field::rand(&mut prng);
            let blinding_var = circuit.create_variable(blinding).unwrap();

            let mut data = [$base_field::from(0u64); TEST_INPUT_LEN];
            for i in 0..TEST_INPUT_LEN {
                data[i] = $base_field::rand(&mut prng);
            }
            let data_vars: Vec<Variable> = data
                .iter()
                .map(|&x| circuit.create_variable(x).unwrap())
                .collect_vec();

            let expected_commitment = FixedLengthRescueCommitment::<
                $base_field,
                TEST_INPUT_LEN,
                TEST_INPUT_LEN_PLUS_ONE,
            >::commit(&data, Some(&blinding))
            .unwrap();

            let commitment_var = circuit.commit(&data_vars, blinding_var).unwrap();

            // Check commitment output consistency
            assert_eq!(
                expected_commitment,
                circuit.witness(commitment_var).unwrap()
            );

            // Check constraints
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            *circuit.witness_mut(commitment_var) = $base_field::from(1_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        };
    }
    #[test]
    fn test_commit_circuit() {
        test_commit_circuit!(FqEd254);
        test_commit_circuit!(FqEd377);
        test_commit_circuit!(FqEd381);
        test_commit_circuit!(FqEd381b);
        test_commit_circuit!(Fq377);
    }
}
