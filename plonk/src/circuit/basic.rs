// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Basic instantiations of Plonk-based constraint systems
use super::{Arithmetization, Circuit, GateId, Variable, WireId};
use crate::{
    circuit::gates::*,
    constants::{compute_coset_representatives, GATE_WIDTH, N_MUL_SELECTORS},
    errors::{CircuitError::*, PlonkError},
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{
    domain::Radix2EvaluationDomain, univariate::DensePolynomial, EvaluationDomain, UVPolynomial,
};
use ark_std::{boxed::Box, format, string::ToString, vec, vec::Vec};
use rayon::prelude::*;

/// A specific Plonk circuit instantiation.
#[derive(Debug, Clone)]
pub struct PlonkCircuit<F>
where
    F: FftField,
{
    /// The number of variables.
    num_vars: usize,

    /// The gate of each (algebraic) constraint
    gates: Vec<Box<dyn Gate<F>>>,
    /// The map from arithmetic/lookup gate wires to variables.
    wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
    /// The IO gates for the list of public input variables.
    pub_input_gate_ids: Vec<GateId>,
    /// The actual values of variables.
    witness: Vec<F>,

    /// The permutation over wires.
    /// Each algebraic gate has 5 wires, i.e., 4 input wires and an output
    /// wire; each lookup gate has a single wire that maps to a witness to
    /// be checked over the lookup table. In total there are 6 * n wires
    /// where n is the (padded) number of arithmetic/lookup gates.  
    /// We build a permutation over the set of wires so that each set of wires
    /// that map to the same witness forms a cycle.
    ///
    /// Each wire is represented by a pair (`WireId, GateId`) so that the wire
    /// is in the `GateId`-th arithmetic/lookup gate and `WireId` represents
    /// the wire type (e.g., 0 represents 1st input wires, 4 represents
    /// output wires, and 5 represents lookup wires).
    wire_permutation: Vec<(WireId, GateId)>,
    /// The extended identity permutation.
    extended_id_permutation: Vec<F>,
    /// The number of wire types. 5 for TurboPlonk and 6 for UltraPlonk.
    num_wire_types: usize,

    /// The evaluation domain for arithmetization of the circuit into various
    /// polynomials. This is only relevant after the circuit is finalized for
    /// arithmetization, by default it is a domain with size 1 (only with
    /// element 0).
    eval_domain: Radix2EvaluationDomain<F>,
}

impl<F: FftField> Default for PlonkCircuit<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FftField> PlonkCircuit<F> {
    /// Construct a new TurboPlonk circuit
    pub fn new() -> Self {
        let zero = F::zero();
        let one = F::one();
        let mut circuit = Self {
            num_vars: 2,
            witness: vec![zero, one],
            gates: vec![],
            // size is `num_wire_types`
            wire_variables: [vec![], vec![], vec![], vec![], vec![], vec![]],
            pub_input_gate_ids: vec![],

            wire_permutation: vec![],
            extended_id_permutation: vec![],
            num_wire_types: GATE_WIDTH + 1,
            eval_domain: Radix2EvaluationDomain::new(1).unwrap(),
        };
        // Constrain variables `0`/`1` to have value 0/1.
        circuit.constant_gate(0, zero).unwrap(); // safe unwrap
        circuit.constant_gate(1, one).unwrap(); // safe unwrap
        circuit
    }

    /// Insert a general (algebraic) gate
    /// * `wire_vars` - wire variables. Each of these variables must be in range
    /// * `gate` - specific gate to be inserted
    /// * `returns` - an error if some verification fails
    pub fn insert_gate(
        &mut self,
        wire_vars: &[Variable; GATE_WIDTH + 1],
        gate: Box<dyn Gate<F>>,
    ) -> Result<(), PlonkError> {
        self.check_finalize_flag(false)?;

        for (wire_var, wire_variable) in wire_vars
            .iter()
            .zip(self.wire_variables.iter_mut().take(GATE_WIDTH + 1))
        {
            wire_variable.push(*wire_var)
        }

        self.gates.push(gate);
        Ok(())
    }

    #[inline]
    /// Checks if a variable is strictly less than the number of variables.
    /// This function must be invoked for each gate as this check is not applied
    /// in the function `insert_gate`
    /// * `var` - variable to check
    /// * `returns` - Error if the variable is out of bound (i.e. >= number of
    ///   variables)
    pub fn check_var_bound(&self, var: Variable) -> Result<(), PlonkError> {
        if var >= self.num_vars {
            return Err(VarIndexOutOfBound(var, self.num_vars).into());
        }
        Ok(())
    }

    /// Check if a list of variables are strictly less than the number of
    /// variables.
    /// * `vars` - variables to check
    /// * `returns` - Error if the variable is out of bound (i.e. >= number of
    ///   variables)
    pub fn check_vars_bound(&self, vars: &[Variable]) -> Result<(), PlonkError> {
        for &var in vars {
            self.check_var_bound(var)?
        }
        Ok(())
    }

    /// Change the value of a variable. Only used for testing.
    // TODO: make this function test only.
    pub fn witness_mut(&mut self, idx: Variable) -> &mut F {
        &mut self.witness[idx]
    }
}

impl<F: FftField> Circuit<F> for PlonkCircuit<F> {
    fn num_gates(&self) -> usize {
        self.gates.len()
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn num_inputs(&self) -> usize {
        self.pub_input_gate_ids.len()
    }

    fn num_wire_types(&self) -> usize {
        self.num_wire_types
    }

    fn public_input(&self) -> Result<Vec<F>, PlonkError> {
        self.pub_input_gate_ids
            .iter()
            .map(|&gate_id| -> Result<F, PlonkError> {
                let var = self.wire_variables[GATE_WIDTH][gate_id];
                self.witness(var)
            })
            .collect::<Result<Vec<F>, PlonkError>>()
    }

    fn check_circuit_satisfiability(&self, pub_input: &[F]) -> Result<(), PlonkError> {
        if pub_input.len() != self.num_inputs() {
            return Err(PubInputLenMismatch(pub_input.len(), self.pub_input_gate_ids.len()).into());
        }
        // Check public I/O gates
        for (i, gate_id) in self.pub_input_gate_ids.iter().enumerate() {
            let pi = pub_input[i];
            self.check_gate(*gate_id, &pi)?;
        }
        // Check rest of the gates
        for gate_id in 0..self.num_gates() {
            if !self.is_io_gate(gate_id) {
                let pi = F::zero();
                self.check_gate(gate_id, &pi)?;
            }
        }

        Ok(())
    }

    fn create_constant_variable(&mut self, val: F) -> Result<Variable, PlonkError> {
        let var = self.create_variable(val)?;
        self.constant_gate(var, val)?;
        Ok(var)
    }

    fn create_variable(&mut self, val: F) -> Result<Variable, PlonkError> {
        self.check_finalize_flag(false)?;
        self.witness.push(val);
        self.num_vars += 1;
        // the index is from `0` to `num_vars - 1`
        Ok(self.num_vars - 1)
    }

    fn create_public_variable(&mut self, val: F) -> Result<Variable, PlonkError> {
        let var = self.create_variable(val)?;
        self.set_variable_public(var)?;
        Ok(var)
    }

    fn set_variable_public(&mut self, var: Variable) -> Result<(), PlonkError> {
        self.check_finalize_flag(false)?;
        self.pub_input_gate_ids.push(self.num_gates());

        // Create an io gate that forces `witness[var] = public_input`.
        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, Box::new(IoGate))?;
        Ok(())
    }

    /// Default zero variable
    fn zero(&self) -> Variable {
        0
    }

    /// Default one variable
    fn one(&self) -> Variable {
        1
    }

    fn witness(&self, idx: Variable) -> Result<F, PlonkError> {
        self.check_var_bound(idx)?;
        Ok(self.witness[idx])
    }

    fn constant_gate(&mut self, var: Variable, constant: F) -> Result<(), PlonkError> {
        self.check_var_bound(var)?;

        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, Box::new(ConstantGate(constant)))?;
        Ok(())
    }

    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(AdditionGate))?;
        Ok(())
    }

    fn add(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? + self.witness(b)?;
        let c = self.create_variable(val)?;
        self.add_gate(a, b, c)?;
        Ok(c)
    }

    fn sub_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(SubtractionGate))?;
        Ok(())
    }

    fn sub(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? - self.witness(b)?;
        let c = self.create_variable(val)?;
        self.sub_gate(a, b, c)?;
        Ok(c)
    }

    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(MultiplicationGate))?;
        Ok(())
    }

    fn mul(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? * self.witness(b)?;
        let c = self.create_variable(val)?;
        self.mul_gate(a, b, c)?;
        Ok(c)
    }

    fn bool_gate(&mut self, a: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;

        let wire_vars = &[a, a, 0, 0, a];
        self.insert_gate(wire_vars, Box::new(BoolGate))?;
        Ok(())
    }

    fn equal_gate(&mut self, a: Variable, b: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;

        let wire_vars = &[a, b, 0, 0, 0];
        self.insert_gate(wire_vars, Box::new(EqualityGate))?;
        Ok(())
    }

    fn pad_gate(&mut self, n: usize) {
        // TODO: FIXME
        // this is interesting...
        // if we insert a PaddingGate
        // the padded gate does not have a gate_id, and will bug
        // when we check circuit satisfiability
        // we temporarily insert equality gate to by pass the issue
        let wire_vars = &[self.zero(), self.zero(), 0, 0, 0];
        for _ in 0..n {
            self.insert_gate(wire_vars, Box::new(EqualityGate)).unwrap();
        }
    }
}

/// Private helper methods
impl<F: FftField> PlonkCircuit<F> {
    fn is_finalized(&self) -> bool {
        self.eval_domain.size() != 1
    }

    /// Re-arrange the order of the gates so that
    /// 1. io gates are in the front.
    /// 2. variable table lookup gate are at the rear so that they do not affect
    /// the range gates when merging the lookup tables.
    ///
    /// Remember to pad gates before calling the method.
    fn rearrange_gates(&mut self) -> Result<(), PlonkError> {
        self.check_finalize_flag(true)?;
        for (gate_id, io_gate_id) in self.pub_input_gate_ids.iter_mut().enumerate() {
            if *io_gate_id > gate_id {
                // Swap gate types
                self.gates.swap(gate_id, *io_gate_id);
                // Swap wire variables
                for i in 0..GATE_WIDTH + 1 {
                    self.wire_variables[i].swap(gate_id, *io_gate_id);
                }
                // Update io gate index
                *io_gate_id = gate_id;
            }
        }

        Ok(())
    }
    // use downcast to check whether a gate is of IoGate type
    fn is_io_gate(&self, gate_id: GateId) -> bool {
        self.gates[gate_id].as_any().is::<IoGate>()
    }

    // pad a finalized circuit to match the evaluation domain, prepared for
    // arithmetization.
    fn pad(&mut self) -> Result<(), PlonkError> {
        self.check_finalize_flag(true)?;
        let n = self.eval_domain.size();
        for _ in self.num_gates()..n {
            self.gates.push(Box::new(PaddingGate));
        }
        for wire_id in 0..self.num_wire_types() {
            self.wire_variables[wire_id].resize(n, self.zero());
        }
        Ok(())
    }

    /// Check that the `gate_id`-th gate is satisfied by the circuit's witness
    /// and the public input value `pub_input`. `gate_id` is guaranteed to
    /// be in the range. The gate equation:
    /// qo * wo = pub_input + q_c +
    ///           q_mul0 * w0 * w1 + q_mul1 * w2 * w3 +
    ///           q_lc0 * w0 + q_lc1 * w1 + q_lc2 * w2 + q_lc3 * w3 +
    ///           q_hash0 * w0 + q_hash1 * w1 + q_hash2 * w2 + q_hash3 * w3 +
    ///           q_ecc * w0 * w1 * w2 * w3 * wo
    fn check_gate(&self, gate_id: Variable, pub_input: &F) -> Result<(), PlonkError> {
        // Compute wire values

        let w_vals: Vec<F> = (0..GATE_WIDTH + 1)
            .map(|i| self.witness[self.wire_variables[i][gate_id]])
            .collect();
        // Compute selector values.
        let q_lc: [F; GATE_WIDTH] = self.gates[gate_id].q_lc();
        let q_mul: [F; N_MUL_SELECTORS] = self.gates[gate_id].q_mul();
        let q_hash: [F; GATE_WIDTH] = self.gates[gate_id].q_hash();
        let q_c = self.gates[gate_id].q_c();
        let q_o = self.gates[gate_id].q_o();
        let q_ecc = self.gates[gate_id].q_ecc();

        // Compute the gate output
        let expected_gate_output = *pub_input
            + q_lc[0] * w_vals[0]
            + q_lc[1] * w_vals[1]
            + q_lc[2] * w_vals[2]
            + q_lc[3] * w_vals[3]
            + q_mul[0] * w_vals[0] * w_vals[1]
            + q_mul[1] * w_vals[2] * w_vals[3]
            + q_ecc * w_vals[0] * w_vals[1] * w_vals[2] * w_vals[3] * w_vals[4]
            + q_hash[0] * w_vals[0].pow(&[5])
            + q_hash[1] * w_vals[1].pow(&[5])
            + q_hash[2] * w_vals[2].pow(&[5])
            + q_hash[3] * w_vals[3].pow(&[5])
            + q_c;
        let gate_output = q_o * w_vals[4];
        if expected_gate_output != gate_output {
            return Err(
                GateCheckFailure(
                    gate_id,
                    format!(
                        "gate: {:?}, wire values: {:?}, pub_input: {}, expected_gate_output: {}, gate_output: {}",
                        self.gates[gate_id],
                        w_vals,
                        pub_input,
                        expected_gate_output,
                        gate_output
                    )
                )
                .into());
        }
        Ok(())
    }

    // Compute the permutation over wires.
    // The circuit is guaranteed to be padded before calling the method.
    #[inline]
    fn compute_wire_permutation(&mut self) {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();
        let m = self.num_vars();

        // Compute the mapping from variables to wires.
        // NOTE: we can use a vector as a map because our variable (the intended "key"
        // value type of the Map) is sorted and match exactly as the
        // non-negative integer ranged from 0 to m. Our current implementation should be
        // slightly faster than using a `HashMap<Variable, Vec<(WireId, GateId)>>` as we
        // avoid any constant overhead from the hashmap read/write.
        let mut variable_wires_map = vec![vec![]; m];
        for (gate_wire_id, variables) in self
            .wire_variables
            .iter()
            .take(self.num_wire_types())
            .enumerate()
        {
            for (gate_id, &var) in variables.iter().enumerate() {
                variable_wires_map[var].push((gate_wire_id, gate_id));
            }
        }

        // Compute the wire permutation
        self.wire_permutation = vec![(0usize, 0usize); self.num_wire_types * n];
        for wires_vec in variable_wires_map.iter_mut() {
            // The list of wires that map to the same variable forms a cycle.
            if !wires_vec.is_empty() {
                // push the first item so that window iterator will visit the last item
                // paired with the first item, forming a cycle
                wires_vec.push(wires_vec[0]);
                for window in wires_vec.windows(2) {
                    self.wire_permutation[window[0].0 * n + window[0].1] = window[1];
                }
                // remove the extra first item pushed at the beginning of the iterator
                wires_vec.pop();
            }
        }
    }

    // Check whether the circuit is finalized. Return an error if the finalizing
    // status is different from the expected status.
    #[inline]
    fn check_finalize_flag(&self, expect_finalized: bool) -> Result<(), PlonkError> {
        if !self.is_finalized() && expect_finalized {
            return Err(UnfinalizedCircuit.into());
        }
        if self.is_finalized() && !expect_finalized {
            return Err(ModifyFinalizedCircuit.into());
        }
        Ok(())
    }

    // Check whether the variable `var` is a boolean value
    // this is used to return error to invalid parameter early in the circuit
    // building development lifecycle, it should NOT be used as a circuit constraint
    // for which you should use bool_gate() instead
    #[inline]
    pub(crate) fn check_bool(&self, var: Variable) -> Result<(), PlonkError> {
        let val = self.witness(var)?;
        if val != F::zero() && val != F::one() {
            Err(ParameterError(
                "Expecting a boolean value, something is wrong with your circuit logic".to_string(),
            )
            .into())
        } else {
            Ok(())
        }
    }

    // Return the variable that maps to a wire `(i, j)` where i is the wire type and
    // j is the gate index. If gate `j` is a padded dummy gate, return zero
    // variable.
    #[inline]
    fn wire_variable(&self, i: WireId, j: GateId) -> Variable {
        match j < self.wire_variables[i].len() {
            true => self.wire_variables[i][j],
            false => self.zero(),
        }
    }

    // getter for all linear combination selector
    #[inline]
    fn q_lc(&self) -> [Vec<F>; GATE_WIDTH] {
        let mut result = [vec![], vec![], vec![], vec![]];
        for gate in &self.gates {
            let q_lc_vec = gate.q_lc();
            result[0].push(q_lc_vec[0]);
            result[1].push(q_lc_vec[1]);
            result[2].push(q_lc_vec[2]);
            result[3].push(q_lc_vec[3]);
        }
        result
    }
    // getter for all multiplication selector
    #[inline]
    fn q_mul(&self) -> [Vec<F>; N_MUL_SELECTORS] {
        let mut result = [vec![], vec![]];
        for gate in &self.gates {
            let q_mul_vec = gate.q_mul();
            result[0].push(q_mul_vec[0]);
            result[1].push(q_mul_vec[1]);
        }
        result
    }
    // getter for all hash selector
    #[inline]
    fn q_hash(&self) -> [Vec<F>; GATE_WIDTH] {
        let mut result = [vec![], vec![], vec![], vec![]];
        for gate in &self.gates {
            let q_hash_vec = gate.q_hash();
            result[0].push(q_hash_vec[0]);
            result[1].push(q_hash_vec[1]);
            result[2].push(q_hash_vec[2]);
            result[3].push(q_hash_vec[3]);
        }
        result
    }
    // getter for all output selector
    #[inline]
    fn q_o(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_o()).collect()
    }
    // getter for all constant selector
    #[inline]
    fn q_c(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_c()).collect()
    }
    // getter for all ecc selector
    #[inline]
    fn q_ecc(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_ecc()).collect()
    }

    // TODO: (alex) try return reference instead of expensive clone
    // getter for all selectors in the following order:
    // q_lc, q_mul, q_hash, q_o, q_c, q_ecc, [q_lookup (if support lookup)]
    #[inline]
    fn all_selectors(&self) -> Vec<Vec<F>> {
        let mut selectors = vec![];
        self.q_lc()
            .as_ref()
            .iter()
            .chain(self.q_mul().as_ref().iter())
            .chain(self.q_hash().as_ref().iter())
            .for_each(|s| selectors.push(s.clone()));
        selectors.push(self.q_o());
        selectors.push(self.q_c());
        selectors.push(self.q_ecc());
        // if self.support_lookup() {
        //     selectors.push(self.q_lookup());
        // }
        selectors
    }
}

/// Private permutation related methods
impl<F: PrimeField> PlonkCircuit<F> {
    /// Copy constraints: precompute the extended permutation over circuit
    /// wires. Refer to Sec 5.2 and Sec 8.1 of https://eprint.iacr.org/2019/953.pdf for more details.
    #[inline]
    fn compute_extended_id_permutation(&mut self) {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();

        // Compute the extended identity permutation
        // id[i*n+j] = k[i] * g^j
        let k: Vec<F> = compute_coset_representatives(self.num_wire_types, Some(n));
        // Precompute domain elements
        let group_elems: Vec<F> = self.eval_domain.elements().collect();
        // Compute extended identity permutation
        self.extended_id_permutation = vec![F::zero(); self.num_wire_types * n];
        for (i, &coset_repr) in k.iter().enumerate() {
            for (j, &group_elem) in group_elems.iter().enumerate() {
                self.extended_id_permutation[i * n + j] = coset_repr * group_elem;
            }
        }
    }

    #[inline]
    fn compute_extended_permutation(&self) -> Result<Vec<F>, PlonkError> {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();

        // The extended wire permutation can be computed as
        // extended_perm[i] = id[wire_perm[i].0 * n + wire_perm[i].1]
        let extended_perm: Vec<F> = self
            .wire_permutation
            .iter()
            .map(|&(wire_id, gate_id)| {
                // if permutation value undefined, return 0
                if wire_id >= self.num_wire_types {
                    F::zero()
                } else {
                    self.extended_id_permutation[wire_id * n + gate_id]
                }
            })
            .collect();
        if extended_perm.len() != self.num_wire_types * n {
            return Err(ParameterError(
                "Length of the extended permutation vector should be number of gate \
                         (including padded dummy gates) * number of wire types"
                    .to_string(),
            )
            .into());
        }
        Ok(extended_perm)
    }
}

/// Methods for finalizing and merging the circuits.
impl<F: PrimeField> PlonkCircuit<F> {
    /// Finalize the setup of the circuit before arithmetization.
    pub fn finalize_for_arithmetization(&mut self) -> Result<(), PlonkError> {
        if self.is_finalized() {
            return Ok(());
        }
        self.eval_domain =
            Radix2EvaluationDomain::new(self.num_gates()).ok_or(PlonkError::DomainCreationError)?;
        self.pad()?;
        self.rearrange_gates()?;
        self.compute_wire_permutation();
        self.compute_extended_id_permutation();
        Ok(())
    }
}

impl<F> Arithmetization<F> for PlonkCircuit<F>
where
    F: PrimeField,
{
    fn srs_size(&self) -> Result<usize, PlonkError> {
        // extra 2 degree for masking polynomial to make snark zero-knowledge
        Ok(self.eval_domain_size()? + 2)
    }

    fn eval_domain_size(&self) -> Result<usize, PlonkError> {
        self.check_finalize_flag(true)?;
        Ok(self.eval_domain.size())
    }

    fn compute_selector_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, PlonkError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        if domain.size() < self.num_gates() {
            return Err(ParameterError(
                "Domain size should be bigger than number of constraint".to_string(),
            )
            .into());
        }
        // order: (lc, mul, hash, o, c, ecc) as specified in spec
        let selector_polys: Vec<_> = self
            .all_selectors()
            .par_iter()
            .map(|selector| DensePolynomial::from_coefficients_vec(domain.ifft(selector)))
            .collect();

        Ok(selector_polys)
    }

    fn compute_extended_permutation_polynomials(
        &self,
    ) -> Result<Vec<DensePolynomial<F>>, PlonkError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let n = domain.size();
        let extended_perm = self.compute_extended_permutation()?;
        let extended_perm_polys: Vec<DensePolynomial<F>> = (0..self.num_wire_types)
            .into_par_iter()
            .map(|i| {
                DensePolynomial::from_coefficients_vec(
                    domain.ifft(&extended_perm[i * n..(i + 1) * n]),
                )
            })
            .collect();
        Ok(extended_perm_polys)
    }

    fn compute_prod_permutation_polynomial(
        &self,
        beta: &F,
        gamma: &F,
    ) -> Result<DensePolynomial<F>, PlonkError> {
        self.check_finalize_flag(true)?;
        let mut product_vec = vec![F::one()];
        let domain = &self.eval_domain;
        let n = domain.size();
        for j in 0..(n - 1) {
            // Nominator
            let mut a = F::one();
            // Denominator
            let mut b = F::one();
            for i in 0..self.num_wire_types {
                let wire_value = self.witness[self.wire_variable(i, j)];
                let tmp = wire_value + gamma;
                a *= tmp + *beta * self.extended_id_permutation[i * n + j];
                let (perm_i, perm_j) = self.wire_permutation[i * n + j];
                b *= tmp + *beta * self.extended_id_permutation[perm_i * n + perm_j];
            }
            let prev_prod = *product_vec.last().ok_or(PlonkError::IndexError)?;
            product_vec.push(prev_prod * a / b);
        }
        domain.ifft_in_place(&mut product_vec);
        Ok(DensePolynomial::from_coefficients_vec(product_vec))
    }

    fn compute_wire_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, PlonkError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        if domain.size() < self.num_gates() {
            return Err(ParameterError(format!(
                "Domain size {} should be bigger than number of constraint {}",
                domain.size(),
                self.num_gates()
            ))
            .into());
        }
        let witness = &self.witness;
        let wire_polys: Vec<_> = self
            .wire_variables
            .par_iter()
            .take(self.num_wire_types())
            .map(|wire_vars| {
                let mut wire_vec: Vec<F> = wire_vars.iter().map(|&var| witness[var]).collect();
                domain.ifft_in_place(&mut wire_vec);
                DensePolynomial::from_coefficients_vec(wire_vec)
            })
            .collect();
        assert_eq!(wire_polys.len(), self.num_wire_types());
        Ok(wire_polys)
    }

    fn compute_pub_input_polynomial(&self) -> Result<DensePolynomial<F>, PlonkError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let mut pub_input_vec = vec![F::zero(); domain.size()];
        self.pub_input_gate_ids.iter().for_each(|&io_gate_id| {
            let var = self.wire_variables[GATE_WIDTH][io_gate_id];
            pub_input_vec[io_gate_id] = self.witness[var];
        });
        domain.ifft_in_place(&mut pub_input_vec);
        Ok(DensePolynomial::from_coefficients_vec(pub_input_vec))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{
        circuit::{Arithmetization, Circuit, PlonkCircuit},
        constants::compute_coset_representatives,
        errors::PlonkError,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;
    use ark_poly::{domain::Radix2EvaluationDomain, univariate::DensePolynomial, EvaluationDomain};
    use ark_std::{test_rng, vec, vec::Vec};

    #[test]
    fn test_circuit_trait() -> Result<(), PlonkError> {
        test_circuit_trait_helper::<FqEd254>()?;
        test_circuit_trait_helper::<FqEd377>()?;
        test_circuit_trait_helper::<FqEd381>()?;
        test_circuit_trait_helper::<Fq377>()
    }

    fn test_circuit_trait_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        // Create secret variables.
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(1u32))?;
        // Constant gate: a = 3.
        circuit.constant_gate(a, F::from(3u32))?;
        // Bool gate: b is bool.
        circuit.bool_gate(b)?;
        // Addition gate: c = a + b = 4.
        let c = circuit.add(a, b)?;
        // Subtraction gate: d = a - b = 2.
        let d = circuit.sub(a, b)?;
        // Multiplication gate: e = c * d = 8
        let e = circuit.mul(c, d)?;
        // Create public variables.
        let f = circuit.create_public_variable(F::from(8u32))?;
        // Equality gate: e = f = 8
        circuit.equal_gate(e, f)?;

        // Check the number of gates:
        // 2 constant gates for default 0/1, 6 arithmetic gates, 1 io gate.
        assert_eq!(circuit.num_gates(), 9);
        // Check the number of variables:
        assert_eq!(circuit.num_vars(), 8);
        // Chech the number of public inputs:
        assert_eq!(circuit.num_inputs(), 1);

        // Check circuit satisfiability
        let pub_input = &[F::from(8u32)];
        let verify = circuit.check_circuit_satisfiability(pub_input);
        assert!(verify.is_ok(), "{:?}", verify.unwrap_err());
        let bad_pub_input = &[F::from(0u32)];
        assert!(circuit.check_circuit_satisfiability(bad_pub_input).is_err());
        // Wrong public input length
        let bad_pub_input = &[F::from(8u32), F::from(8u32)];
        assert!(circuit.check_circuit_satisfiability(bad_pub_input).is_err());

        Ok(())
    }

    #[test]
    fn test_add() -> Result<(), PlonkError> {
        test_add_helper::<FqEd254>()?;
        test_add_helper::<FqEd377>()?;
        test_add_helper::<FqEd381>()?;
        test_add_helper::<Fq377>()
    }

    fn test_add_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(1u32))?;
        let c = circuit.add(a, b)?;

        // Check circuits.
        assert_eq!(circuit.witness(c)?, F::from(4u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(c) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.add(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_sub() -> Result<(), PlonkError> {
        test_sub_helper::<FqEd254>()?;
        test_sub_helper::<FqEd377>()?;
        test_sub_helper::<FqEd381>()?;
        test_sub_helper::<Fq377>()
    }

    fn test_sub_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(1u32))?;
        let c = circuit.sub(a, b)?;

        // Check circuits.
        assert_eq!(circuit.witness(c)?, F::from(2u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(c) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.sub(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_mul() -> Result<(), PlonkError> {
        test_mul_helper::<FqEd254>()?;
        test_mul_helper::<FqEd377>()?;
        test_mul_helper::<FqEd381>()?;
        test_mul_helper::<Fq377>()
    }

    fn test_mul_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(2u32))?;
        let c = circuit.mul(a, b)?;

        // Check circuits.
        assert_eq!(circuit.witness(c)?, F::from(6u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(c) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.mul(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_equal_gate() -> Result<(), PlonkError> {
        test_equal_gate_helper::<FqEd254>()?;
        test_equal_gate_helper::<FqEd377>()?;
        test_equal_gate_helper::<FqEd381>()?;
        test_equal_gate_helper::<Fq377>()
    }
    fn test_equal_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(3u32))?;
        circuit.equal_gate(a, b)?;

        // Check circuits.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(b) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.equal_gate(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_bool() -> Result<(), PlonkError> {
        test_bool_helper::<FqEd254>()?;
        test_bool_helper::<FqEd377>()?;
        test_bool_helper::<FqEd381>()?;
        test_bool_helper::<Fq377>()
    }

    fn test_bool_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(0u32))?;
        circuit.bool_gate(a)?;

        // Check circuits.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.bool_gate(circuit.num_vars()).is_err());

        Ok(())
    }

    #[test]
    fn test_constant() -> Result<(), PlonkError> {
        test_constant_helper::<FqEd254>()?;
        test_constant_helper::<FqEd377>()?;
        test_constant_helper::<FqEd381>()?;
        test_constant_helper::<Fq377>()
    }
    fn test_constant_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(10u32))?;
        circuit.constant_gate(a, F::from(10u32))?;

        // Check circuits.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit
            .constant_gate(circuit.num_vars(), F::from(0u32))
            .is_err());

        Ok(())
    }

    #[test]
    fn test_io_gate() -> Result<(), PlonkError> {
        test_io_gate_helper::<FqEd254>()?;
        test_io_gate_helper::<FqEd377>()?;
        test_io_gate_helper::<FqEd381>()?;
        test_io_gate_helper::<Fq377>()
    }

    fn test_io_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::<F>::new();
        let b = circuit.create_variable(F::from(0u32))?;
        let a = circuit.create_public_variable(F::from(1u32))?;
        circuit.bool_gate(a)?;
        circuit.bool_gate(b)?;
        circuit.set_variable_public(b)?;

        // Different valid public inputs should all pass the circuit check.
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(1u32), F::from(0u32)])
            .is_ok());
        *circuit.witness_mut(a) = F::from(0u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(0u32)])
            .is_ok());
        *circuit.witness_mut(b) = F::from(1u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(1u32)])
            .is_ok());

        // Invalid public inputs should fail the circuit check.
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(1u32)])
            .is_err());
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(1u32)])
            .is_err());
        *circuit.witness_mut(a) = F::from(0u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(2u32)])
            .is_err());
        *circuit.witness_mut(b) = F::from(2u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(2u32)])
            .is_err());

        Ok(())
    }

    #[test]
    fn test_io_gate_multi_inputs() -> Result<(), PlonkError> {
        test_io_gate_multi_inputs_helper::<FqEd254>()?;
        test_io_gate_multi_inputs_helper::<FqEd377>()?;
        test_io_gate_multi_inputs_helper::<FqEd381>()?;
        test_io_gate_multi_inputs_helper::<Fq377>()
    }
    fn test_io_gate_multi_inputs_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::<F>::new();
        let a = circuit.create_public_variable(F::from(1u32))?;
        let b = circuit.create_public_variable(F::from(2u32))?;
        let c = circuit.create_public_variable(F::from(3u32))?;
        circuit.add_gate(a, b, c)?;

        // Good path
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(1u32), F::from(2u32), F::from(3u32)])
            .is_ok());
        // The circuit check should fail given a public input with wrong order.
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(1u32), F::from(3u32)])
            .is_err());
        // A different valid public input should pass the circuit check.
        *circuit.witness_mut(a) = F::from(4u32);
        *circuit.witness_mut(b) = F::from(8u32);
        *circuit.witness_mut(c) = F::from(12u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(4u32), F::from(8u32), F::from(12u32)])
            .is_ok());
        // An invalid public input should fail the circuit check.
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(8u32), F::from(12u32)])
            .is_err());

        Ok(())
    }

    fn create_turbo_plonk_instance<F: PrimeField>() -> Result<(PlonkCircuit<F>, Vec<F>), PlonkError>
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_public_variable(F::from(1u32))?;
        circuit.constant_gate(a, F::from(3u32))?;
        circuit.bool_gate(b)?;
        let c = circuit.add(a, b)?;
        let d = circuit.sub(a, b)?;
        let e = circuit.mul(c, d)?;
        let f = circuit.create_public_variable(F::from(8u32))?;
        circuit.equal_gate(e, f)?;

        Ok((circuit, vec![F::from(1u32), F::from(8u32)]))
    }

    /// Tests related to permutations
    #[test]
    fn test_compute_extended_permutation() -> Result<(), PlonkError> {
        test_compute_extended_permutation_helper::<FqEd254>()?;
        test_compute_extended_permutation_helper::<FqEd377>()?;
        test_compute_extended_permutation_helper::<FqEd381>()?;
        test_compute_extended_permutation_helper::<Fq377>()
    }

    fn test_compute_extended_permutation_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(2u32))?;
        let b = circuit.create_public_variable(F::from(3u32))?;
        let c = circuit.add(a, b)?;
        let d = circuit.add(circuit.one(), a)?;
        let _ = circuit.mul(c, d)?;

        // Create a UltraPlonk instance
        let (mut circuit, _) = create_turbo_plonk_instance::<F>()?;
        check_wire_permutation_and_extended_id_permutation(&mut circuit)?;

        Ok(())
    }

    fn check_wire_permutation_and_extended_id_permutation<F: PrimeField>(
        circuit: &mut PlonkCircuit<F>,
    ) -> Result<(), PlonkError> {
        let domain = Radix2EvaluationDomain::<F>::new(circuit.num_gates())
            .ok_or(PlonkError::DomainCreationError)?;
        let n = domain.size();
        circuit.eval_domain = domain;

        // Check wire permutation's correctness
        circuit.pad()?;
        circuit.compute_wire_permutation();
        let mut visit_wire = vec![false; circuit.num_wire_types * n];
        let mut visit_variable = vec![false; circuit.num_vars()];

        for i in 0..circuit.num_wire_types {
            for j in 0..n {
                if visit_wire[i * n + j] {
                    continue;
                }
                // Compute the cycle's variable.
                let cycle_var = circuit.wire_variable(i, j);
                // The variable shouldn't have been marked yet.
                assert_eq!(visit_variable[cycle_var], false);
                visit_variable[cycle_var] = true;

                // Visit the cycle.
                let mut wire_id = i;
                let mut gate_id = j;
                visit_wire[i * n + j] = true;
                loop {
                    let (next_wire_id, next_gate_id) =
                        circuit.wire_permutation[wire_id * n + gate_id];
                    // Break the loop if back to the starting wire.
                    if next_wire_id == i && next_gate_id == j {
                        break;
                    }
                    let next_var = circuit.wire_variable(next_wire_id, next_gate_id);
                    // The adjacent wire's variable should be the same.
                    assert_eq!(cycle_var, next_var);
                    // The adjacent wire shouldn't have been marked yet.
                    assert_eq!(visit_wire[next_wire_id * n + next_gate_id], false);
                    visit_wire[next_wire_id * n + next_gate_id] = true;
                    wire_id = next_wire_id;
                    gate_id = next_gate_id;
                }
            }
        }

        // Check the correctness of the extended id permutation
        circuit.compute_extended_id_permutation();
        // Compute quadratic non-residues and group elements.
        let k: Vec<F> = compute_coset_representatives(circuit.num_wire_types, Some(n));
        let group_elems: Vec<F> = domain.elements().collect();
        for i in 0..circuit.num_wire_types {
            for j in 0..n {
                assert_eq!(
                    k[i] * group_elems[j],
                    circuit.extended_id_permutation[i * n + j]
                )
            }
        }

        Ok(())
    }

    #[test]
    fn test_finalized_flag() -> Result<(), PlonkError> {
        test_finalized_flag_helper::<FqEd254>()?;
        test_finalized_flag_helper::<FqEd377>()?;
        test_finalized_flag_helper::<FqEd381>()?;
        test_finalized_flag_helper::<Fq377>()
    }

    fn test_finalized_flag_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        // Should not call arithmetization methods before finalizing the circuit.
        assert!(circuit.compute_selector_polynomials().is_err());
        assert!(circuit.compute_extended_permutation_polynomials().is_err());
        assert!(circuit.compute_pub_input_polynomial().is_err());
        assert!(circuit.compute_wire_polynomials().is_err());
        assert!(circuit
            .compute_prod_permutation_polynomial(&F::one(), &F::one())
            .is_err());

        // Should not insert gates or add variables after finalizing the circuit.
        circuit.finalize_for_arithmetization()?;
        assert!(circuit.create_variable(F::one()).is_err());
        assert!(circuit.create_public_variable(F::one()).is_err());
        assert!(circuit.add_gate(0, 0, 0).is_err());
        assert!(circuit.sub_gate(0, 0, 0).is_err());
        assert!(circuit.mul_gate(0, 0, 0).is_err());
        assert!(circuit.constant_gate(0, F::one()).is_err());
        assert!(circuit.bool_gate(0).is_err());
        assert!(circuit.equal_gate(0, 0).is_err());

        Ok(())
    }

    // Test arithmetizations
    //
    #[test]
    fn test_arithmetization() -> Result<(), PlonkError> {
        test_arithmetization_helper::<FqEd254>()?;
        test_arithmetization_helper::<FqEd377>()?;
        test_arithmetization_helper::<FqEd381>()?;
        test_arithmetization_helper::<Fq377>()
    }

    fn test_arithmetization_helper<F: PrimeField>() -> Result<(), PlonkError> {
        // Create the TurboPlonk circuit
        let (mut circuit, pub_inputs) = create_turbo_plonk_instance::<F>()?;
        circuit.finalize_for_arithmetization()?;
        test_arithmetization_for_circuit(circuit, pub_inputs)?;

        // Create the UltraPlonk circuit
        let (mut circuit, pub_inputs) = create_turbo_plonk_instance::<F>()?;
        circuit.finalize_for_arithmetization()?;
        // test_arithmetization_for_lookup_circuit(&circuit)?;
        test_arithmetization_for_circuit(circuit, pub_inputs)?;

        Ok(())
    }

    // Check that the polynomial `poly` is consistent with the evaluations `evals`
    // over the domain.
    fn check_polynomial<F: PrimeField>(poly: &DensePolynomial<F>, evals: &[F]) {
        let domain = Radix2EvaluationDomain::new(evals.len()).unwrap();
        let poly_eval = poly.evaluate_over_domain_by_ref(domain);
        for (&a, &b) in poly_eval.evals.iter().zip(evals.iter()) {
            assert_eq!(a, b);
        }
    }

    pub(crate) fn test_arithmetization_for_circuit<F: PrimeField>(
        circuit: PlonkCircuit<F>,
        pub_inputs: Vec<F>,
    ) -> Result<(), PlonkError> {
        // Check arithmetizations
        let n = circuit.eval_domain.size();

        // Check selector polynomials
        let selector_polys = circuit.compute_selector_polynomials()?;
        selector_polys
            .iter()
            .zip(circuit.all_selectors().iter())
            .for_each(|(poly, evals)| check_polynomial(poly, evals));

        // Check wire witness polynomials
        let wire_polys = circuit.compute_wire_polynomials()?;
        for (poly, wire_vars) in wire_polys
            .iter()
            .zip(circuit.wire_variables.iter().take(circuit.num_wire_types()))
        {
            let wire_evals: Vec<F> = wire_vars.iter().map(|&var| circuit.witness[var]).collect();
            check_polynomial(poly, &wire_evals);
        }

        // Check public input polynomial
        let pi_poly = circuit.compute_pub_input_polynomial()?;
        let mut pi_evals = pub_inputs;
        pi_evals.extend(vec![F::zero(); n - 2]);
        check_polynomial(&pi_poly, &pi_evals);

        // Check extended permutation polynomials
        let sigma_polys = circuit.compute_extended_permutation_polynomials()?;
        let extended_perm: Vec<F> = circuit
            .wire_permutation
            .iter()
            .map(|&(i, j)| circuit.extended_id_permutation[i * n + j])
            .collect();
        for (i, poly) in sigma_polys.iter().enumerate() {
            check_polynomial(poly, &extended_perm[i * n..(i + 1) * n]);
        }

        // Check grand product polynomial for permutation
        let rng = &mut test_rng();
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let prod_poly = circuit.compute_prod_permutation_polynomial(&beta, &gamma)?;
        let mut prod_evals = vec![F::one()];
        for j in 0..(n - 1) {
            // Nominator
            let mut a = F::one();
            // Denominator
            let mut b = F::one();
            for i in 0..circuit.num_wire_types {
                let wire_value = circuit.witness[circuit.wire_variable(i, j)];
                a *= wire_value + beta * circuit.extended_id_permutation[i * n + j] + gamma;
                b *= wire_value + beta * extended_perm[i * n + j] + gamma;
            }
            let prod = prod_evals[j] * a / b;
            prod_evals.push(prod);
        }
        check_polynomial(&prod_poly, &prod_evals);

        Ok(())
    }
}
