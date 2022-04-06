// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a PRF.

use crate::utils::pad_with;
use jf_hashes::{RescueParameter, STATE_SIZE};
use jf_plonk::{
    circuit::{customized::rescue::RescueGadget, Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};

/// Circuit implementation of a PRF.
pub trait PrfGadget {
    /// PRF many to one
    /// * `key` - key variable
    /// * `input` - input variables,
    /// * `returns` variables that refers to the output
    fn eval_prf(&mut self, key: Variable, input: &[Variable]) -> Result<Variable, PlonkError>;
}

impl<F> PrfGadget for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn eval_prf(&mut self, key: Variable, input: &[Variable]) -> Result<Variable, PlonkError> {
        // pad input: it is ok to pad with zeroes, PRF instance is bound to a specific
        // input length

        let mut input_vec = input.to_vec();
        pad_with(&mut input_vec, STATE_SIZE, self.zero());
        self.rescue_full_state_keyed_sponge_no_padding(key, &input_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::PrfGadget;
    use crate::prf::{PrfKey, PRF};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::UniformRand;
    use ark_std::vec::Vec;
    use itertools::Itertools;
    use jf_plonk::circuit::{Circuit, PlonkCircuit, Variable};

    macro_rules! test_prf_circuit {
        ($base_field:tt) => {
            let mut circuit: PlonkCircuit<$base_field> = PlonkCircuit::new_turbo_plonk();
            let mut prng = ark_std::test_rng();
            let rand_scalar = $base_field::rand(&mut prng);
            let key = PrfKey::from(rand_scalar);
            let key_var = circuit.create_variable(rand_scalar).unwrap();
            let input_len = 10;
            let mut data: Vec<$base_field> = (0..input_len)
                .map(|_| $base_field::rand(&mut prng))
                .collect_vec();
            let data_vars: Vec<Variable> = data
                .iter()
                .map(|&x| circuit.create_variable(x).unwrap())
                .collect_vec();

            let prf = PRF::new(input_len, 1);
            let expected_prf_output = prf.eval(&key, &mut data).unwrap();

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
