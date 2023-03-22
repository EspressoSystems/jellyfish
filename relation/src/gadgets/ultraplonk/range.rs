// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Range proof gates.
use crate::{
    errors::CircuitError::{self, ParameterError},
    Circuit, PlonkCircuit, Variable,
};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{string::ToString, vec::Vec};

impl<F: PrimeField> PlonkCircuit<F> {
    /// Constrain a variable to be within the [0, 2^{bit_len}) range
    /// Return error if one of the following holds:
    /// 1. the variable is invalid;
    /// 2. `RANGE_BIT_LEN` equals zero or does not divide `bit_len`;
    /// 3. the circuit does not support lookup.
    pub(crate) fn range_gate_with_lookup(
        &mut self,
        a: Variable,
        bit_len: usize,
    ) -> Result<(), CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        let range_size = self.range_size()?;
        if bit_len == 0 {
            return Err(ParameterError("bit_len cannot be zero".to_string()));
        }
        if bit_len % range_bit_len != 0 {
            return Err(ParameterError(
                "circuit.range_bit_len does not divide bit_len".to_string(),
            ));
        }
        self.check_var_bound(a)?;
        let len = bit_len / range_bit_len;
        let reprs_le = decompose_le(self.witness(a)?, len, range_bit_len);
        let reprs_le_vars: Vec<Variable> = reprs_le
            .iter()
            .map(|&val| self.create_variable(val))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // add range gates for decomposed variables
        for &var in reprs_le_vars.iter() {
            self.add_range_check_variable(var)?;
        }

        // add linear combination gates
        self.decomposition_gate(reprs_le_vars, a, F::from(range_size as u64))?;

        Ok(())
    }

    /// The number of range blocks, i.e., the minimal integer such that
    /// RANGE_SIZE^NUM_RANGES >= p,
    #[inline]
    pub fn num_range_blocks(&self) -> Result<usize, CircuitError> {
        Ok(F::MODULUS_BIT_SIZE as usize / self.range_bit_len()? + 1)
    }
}

/// Decompose `val` into `a_0`, ..., `a_{len-1}` s.t.
/// val = a_0 + RANGE_SIZE * a_1 + ... + RANGE_SIZE^{len-1} * a_{len-1}
fn decompose_le<F: PrimeField>(val: F, len: usize, range_bit_len: usize) -> Vec<F> {
    let repr_le = val.into_bigint().to_bits_le();
    let mut res: Vec<F> = repr_le
        .chunks(range_bit_len)
        .map(|vec| {
            let mut elem = 0;
            for &b in vec.iter().rev() {
                if !b {
                    elem <<= 1;
                } else {
                    elem = (elem << 1) + 1;
                }
            }
            F::from(elem as u64)
        })
        .collect();
    res.resize(len, F::zero());

    res
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::rand::Rng;
    use jf_utils::test_rng;

    const RANGE_BIT_LEN_FOR_TEST: usize = 8;
    const RANGE_SIZE_FOR_TEST: usize = 256;

    #[test]
    fn test_decompose_le() {
        test_decompose_le_helper::<FqEd254>();
        test_decompose_le_helper::<FqEd377>();
        test_decompose_le_helper::<FqEd381>();
        test_decompose_le_helper::<Fq377>();
    }
    fn test_decompose_le_helper<F: PrimeField>() {
        let len = F::MODULUS_BIT_SIZE as usize / RANGE_BIT_LEN_FOR_TEST + 1;
        let mut rng = test_rng();
        for _ in 0..10 {
            let val = F::rand(&mut rng);
            let repr_le = decompose_le(val, len, RANGE_BIT_LEN_FOR_TEST);
            assert_eq!(repr_le.len(), len);
            check_decomposition(repr_le, val);
        }
    }
    // check that val = a_0 + RANGE_SIZE * a_1 + ... + RANGE_SIZE^{len-1} *
    // a_{len-1}
    fn check_decomposition<F: PrimeField>(a: Vec<F>, val: F) {
        let (expected_val, _) = a.iter().fold((F::zero(), F::one()), |(acc, base), &x| {
            (acc + base * x, base * F::from(RANGE_SIZE_FOR_TEST as u64))
        });
        assert_eq!(expected_val, val);
    }

    #[test]
    fn test_range_gate_with_lookup() -> Result<(), CircuitError> {
        test_range_gate_with_lookup_helper::<FqEd254>()?;
        test_range_gate_with_lookup_helper::<FqEd377>()?;
        test_range_gate_with_lookup_helper::<FqEd381>()?;
        test_range_gate_with_lookup_helper::<Fq377>()
    }
    fn test_range_gate_with_lookup_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        let mut rng = test_rng();
        let bit_len = RANGE_BIT_LEN_FOR_TEST * 4;

        // Good path
        let a = (0..10)
            .map(|_| circuit.create_variable(F::from(rng.gen_range(0..u32::MAX))))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        for &var in a.iter() {
            circuit.range_gate_with_lookup(var, bit_len)?;
        }
        circuit.range_gate_with_lookup(circuit.zero(), RANGE_BIT_LEN_FOR_TEST)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Error paths
        //
        // if mess up the witness value, should fail
        let tmp = circuit.witness(a[0])?;
        *circuit.witness_mut(a[0]) = F::from(u32::MAX as u64 + 1);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(a[0]) = tmp;

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        // Should fail when the value = 2^RANGE_BIT_LEN_FOR_TEST
        let a_var = circuit.create_variable(F::from(1u32 << RANGE_BIT_LEN_FOR_TEST))?;
        circuit.range_gate_with_lookup(a_var, RANGE_BIT_LEN_FOR_TEST)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Should fail when the value = 2^{2*RANGE_BIT_LEN_FOR_TEST}
        let a_var = circuit.create_variable(F::from(1u32 << (2 * RANGE_BIT_LEN_FOR_TEST)))?;
        circuit.range_gate_with_lookup(a_var, 2 * RANGE_BIT_LEN_FOR_TEST)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        let zero_var = circuit.zero();
        // bit_len = 0
        assert!(circuit.range_gate_with_lookup(zero_var, 0).is_err());
        // bit_len % RANGE_BIT_LEN_FOR_TEST != 0
        assert!(circuit
            .range_gate_with_lookup(zero_var, bit_len + 1)
            .is_err());
        // Check variable out of bound error.
        assert!(circuit
            .range_gate_with_lookup(circuit.num_vars(), bit_len)
            .is_err());
        // TurboPlonk shouldn't be able to use the gate
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        assert!(circuit.range_gate_with_lookup(0, bit_len).is_err());

        Ok(())
    }
}
