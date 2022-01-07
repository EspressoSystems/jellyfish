//! Lookup gates over variable tables.

use crate::{
    circuit::{customized::ultraplonk::gates::LookupGate, Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use ark_ff::PrimeField;
use ark_std::{boxed::Box, cmp::max, vec::Vec};

impl<F: PrimeField> PlonkCircuit<F> {
    /// Create a table with keys/values
    ///     [table_id, ..., table_id + n - 1] and
    ///     [table_vars[0], ..., table_vars[n - 1]];
    /// and create a list of variable tuples to be looked up:
    ///     [lookup_vars[0], ..., lookup_vars[m - 1]];
    ///
    /// w.l.o.g we assume n = m as we can pad with dummy tuples when n != m
    pub fn create_table_and_lookup_variables(
        &mut self,
        lookup_vars: &[(Variable, Variable, Variable)],
        table_vars: &[(Variable, Variable)],
    ) -> Result<(), PlonkError> {
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
        // update lookup keys for domain separation.
        let lookup_keys: Vec<Variable> = lookup_vars
            .iter()
            .map(|&(key, ..)| self.add_constant(key, &F::from(self.num_table_elems() as u32)))
            .collect::<Result<Vec<_>, _>>()?;
        let n_gate = self.num_gates();
        (*self.table_gate_ids_mut()).push((n_gate, n));
        for i in 0..n {
            let (key, val0, val1) = match i < lookup_vars.len() {
                true => (lookup_keys[i], lookup_vars[i].1, lookup_vars[i].2),
                false => (self.zero(), self.zero(), self.zero()),
            };
            let (table_val0, table_val1) = match i < table_vars.len() {
                true => table_vars[i],
                false => (self.zero(), self.zero()),
            };
            let wire_vars = [key, val0, val1, table_val0, table_val1];
            self.insert_gate(&wire_vars, Box::new(LookupGate))?;
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
    use ark_std::{test_rng, vec};

    #[test]
    fn test_lookup_table() -> Result<(), PlonkError> {
        test_lookup_table_helper::<FqEd254>()?;
        test_lookup_table_helper::<FqEd377>()?;
        test_lookup_table_helper::<FqEd381>()?;
        test_lookup_table_helper::<Fq377>()
    }
    fn test_lookup_table_helper<F: PrimeField>() -> Result<(), PlonkError> {
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
        for i in 0..n {
            let val0 = circuit.witness(table_vars[i].0)?;
            let val1 = circuit.witness(table_vars[i].1)?;
            let key_var = circuit.create_variable(F::from(i as u32))?;
            let val0_var = circuit.create_variable(val0)?;
            let val1_var = circuit.create_variable(val1)?;
            lookup_vars.push((key_var, val0_var, val1_var));
        }
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

        Ok(())
    }
}
