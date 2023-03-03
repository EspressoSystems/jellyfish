// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Lookup gates over variable tables.

use crate::{errors::CircuitError, gates::LookupGate, Circuit, PlonkCircuit, Variable};
use ark_ff::PrimeField;
use ark_std::{boxed::Box, cmp::max};

impl<F: PrimeField> PlonkCircuit<F> {
    /// Create a table with keys/values
    ///     [0, ..., n - 1] and
    ///     [table_vars\[0\], ..., table_vars\[n - 1\]];
    /// and create a list of variable tuples to be looked up:
    ///     [lookup_vars\[0\], ..., lookup_vars\[m - 1\]];
    ///
    /// w.l.o.g we assume n = m as we can pad with dummy tuples when n != m
    pub fn create_table_and_lookup_variables(
        &mut self,
        lookup_vars: &[(Variable, Variable, Variable)],
        table_vars: &[(Variable, Variable)],
    ) -> Result<(), CircuitError> {
        for lookup_var in lookup_vars.iter() {
            self.check_var_bound(lookup_var.0)?;
            self.check_var_bound(lookup_var.1)?;
            self.check_var_bound(lookup_var.2)?;
        }
        for table_var in table_vars.iter() {
            self.check_var_bound(table_var.0)?;
            self.check_var_bound(table_var.1)?;
        }
        let n = max(lookup_vars.len(), table_vars.len());
        let n_gate = self.num_gates();
        (*self.table_gate_ids_mut()).push((n_gate, n));
        let table_ctr = F::from(self.table_gate_ids_mut().len() as u64);
        for i in 0..n {
            let (q_dom_sep, key, val0, val1) = match i < lookup_vars.len() {
                true => (
                    table_ctr,
                    lookup_vars[i].0,
                    lookup_vars[i].1,
                    lookup_vars[i].2,
                ),
                false => (F::zero(), self.zero(), self.zero(), self.zero()),
            };
            let (table_dom_sep, table_key, table_val0, table_val1) = match i < table_vars.len() {
                true => (
                    table_ctr,
                    F::from(i as u64),
                    table_vars[i].0,
                    table_vars[i].1,
                ),
                false => (F::zero(), F::zero(), self.zero(), self.zero()),
            };
            let wire_vars = [key, val0, val1, table_val0, table_val1];

            self.insert_gate(
                &wire_vars,
                Box::new(LookupGate {
                    q_dom_sep,
                    table_dom_sep,
                    table_key,
                }),
            )?;
        }
        *self.num_table_elems_mut() += n;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::vec;
    use jf_utils::test_rng;

    #[test]
    fn test_lookup_table() -> Result<(), CircuitError> {
        test_lookup_table_helper::<FqEd254>()?;
        test_lookup_table_helper::<FqEd377>()?;
        test_lookup_table_helper::<FqEd381>()?;
        test_lookup_table_helper::<Fq377>()
    }
    fn test_lookup_table_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(4);
        let mut rng = test_rng();

        // create table variables
        let mut table_vars = vec![];
        let n = 10;
        for _ in 0..n {
            let val0 = circuit.create_variable(F::rand(&mut rng))?;
            let val1 = circuit.create_variable(F::rand(&mut rng))?;
            table_vars.push((val0, val1));
        }
        // create lookup variables
        let mut lookup_vars = vec![];
        table_vars
            .iter()
            .enumerate()
            .try_for_each(|(i, (idx0, idx1))| {
                let val0 = circuit.witness(*idx0)?;
                let val1 = circuit.witness(*idx1)?;
                let key_var = circuit.create_variable(F::from(i as u32))?;
                let val0_var = circuit.create_variable(val0)?;
                let val1_var = circuit.create_variable(val1)?;
                lookup_vars.push((key_var, val0_var, val1_var));
                Ok(())
            })?;
        // add lookup variables and tables
        circuit.create_table_and_lookup_variables(&lookup_vars, &table_vars)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // the number of added lookup vars is less than the added table size
        circuit.create_table_and_lookup_variables(&lookup_vars[..n - 1], &table_vars)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // the number of added lookup vars is larger than the added table size
        for i in 0..n {
            // add a new lookup var
            lookup_vars.push(lookup_vars[i]);
        }
        circuit.create_table_and_lookup_variables(&lookup_vars, &table_vars)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Error paths
        // lookup variable outside the table.
        lookup_vars[0].1 = circuit.zero();
        circuit.create_table_and_lookup_variables(&lookup_vars[..1], &table_vars)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // out-of-bound variables
        let bad_lookup_vars = vec![(circuit.num_vars(), circuit.zero(), circuit.zero())];
        let bad_table_vars = vec![(circuit.num_vars(), circuit.zero())];
        assert!(circuit
            .create_table_and_lookup_variables(&bad_lookup_vars, &table_vars)
            .is_err());
        assert!(circuit
            .create_table_and_lookup_variables(&lookup_vars, &bad_table_vars)
            .is_err());

        // A lookup over a separate table should not satisfy the circuit.
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(4);
        let mut rng = test_rng();

        let val0 = circuit.create_variable(F::rand(&mut rng))?;
        let val1 = circuit.create_variable(F::rand(&mut rng))?;
        let table_vars_1 = vec![(val0, val1)];
        let val2 = circuit.create_variable(F::rand(&mut rng))?;
        let val3 = circuit.create_variable(F::rand(&mut rng))?;
        let table_vars_2 = vec![(val2, val3)];
        let val2 = circuit.witness(table_vars_2[0].0)?;
        let val3 = circuit.witness(table_vars_2[0].1)?;
        let val2_var = circuit.create_variable(val2)?;
        let val3_var = circuit.create_variable(val3)?;
        let lookup_vars_1 = vec![(circuit.zero(), val2_var, val3_var)];

        circuit.create_table_and_lookup_variables(&lookup_vars_1, &table_vars_2)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        circuit.create_table_and_lookup_variables(&lookup_vars_1, &table_vars_1)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }
}
