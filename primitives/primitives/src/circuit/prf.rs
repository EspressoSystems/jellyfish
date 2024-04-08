// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a PRF.

use crate::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, PlonkCircuit, Variable};

use super::rescue::RescueNativeGadget;

/// Circuit implementation of a PRF.
pub trait PRFGadget {
    /// PRF many to one
    /// * `key` - key variable
    /// * `input` - input variables,
    /// * `returns` variables that refers to the output
    fn eval_prf(&mut self, key: Variable, input: &[Variable]) -> Result<Variable, CircuitError>;
}

impl<F> PRFGadget for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn eval_prf(&mut self, key: Variable, input: &[Variable]) -> Result<Variable, CircuitError> {
        RescueNativeGadget::<F>::rescue_full_state_keyed_sponge_with_zero_padding(self, key, input)
    }
}

#[cfg(test)]
mod tests {
    use super::PRFGadget;
    use crate::prf::{RescuePRF, PRF};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::UniformRand;
    use ark_std::vec::Vec;
    use jf_relation::{Circuit, PlonkCircuit, Variable};

    macro_rules! test_prf_circuit {
        ($base_field:tt) => {
            let mut circuit: PlonkCircuit<$base_field> = PlonkCircuit::new_turbo_plonk();
            let mut prng = jf_utils::test_rng();
            let rand_scalar = $base_field::rand(&mut prng);
            let key_var = circuit.create_variable(rand_scalar).unwrap();
            let input_len = 10;
            let mut data = [$base_field::from(0u8); 10];
            for i in 0..input_len {
                data[i] = $base_field::rand(&mut prng);
            }
            let data_vars: Vec<Variable> = data
                .iter()
                .map(|&x| circuit.create_variable(x).unwrap())
                .collect();

            let expected_prf_output =
                RescuePRF::<$base_field, 10, 1>::evaluate(&rand_scalar, &data).unwrap();
            let prf_var = circuit.eval_prf(key_var, &data_vars).unwrap();

            // Check prf output consistency
            assert_eq!(expected_prf_output[0], circuit.witness(prf_var).unwrap());

            // Check constraints
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            *circuit.witness_mut(prf_var) = $base_field::from(1_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        };
    }

    #[test]
    fn test_prf_circuit() {
        test_prf_circuit!(FqEd254);
        test_prf_circuit!(FqEd377);
        test_prf_circuit!(FqEd381);
        test_prf_circuit!(FqEd381b);
        test_prf_circuit!(Fq377);
    }
}
