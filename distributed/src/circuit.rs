use std::collections::HashSet;

use ark_bls12_381::Fr;
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use fn_timer::fn_timer;
use jf_plonk::{
    circuit::{GateId, Variable},
    constants::GATE_WIDTH,
    errors::{
        CircuitError::{self, *},
        PlonkError,
    },
};
use jf_primitives::{
    circuit::merkle_tree::MerkleNodeVars,
    merkle_tree::{FilledMTBuilder, MerkleLeafProof, MerklePath, NodePos},
};
use jf_rescue::{RescueParameter, ROUNDS, STATE_SIZE};
use once_cell::sync::Lazy;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use crate::config::CIRCUIT_CONFIG;

/// A re-implementation of Jellyfish's Gate.
/// We converted the circuit generation code into a parallelizable form,
/// but found that the original gates are not freed after the circuit is generated.
/// For large circuits, they can take up about 10-20GB of memory.
/// Our new implementation does not have this problem,
/// although it is not generic and only supports BLS12-381.
/// In addition, our `Gate` only takes 3 bytes of memory and is much smaller than
/// the original one, which may take up to 4 Fr elements.
#[derive(Clone)]
pub enum GateType {
    Padding,
    Zero,
    One,
    Addition,
    Equality,
    Multiplication,
    Bool,
    Io,
    FifthRoot,
    CondSelect,
    RescueAddConstant(u8),
    RescueAffine(u8, u8),
    Power5NonLinear(u8, u8),
    MidNode,
}

#[derive(Clone)]
pub struct Gate {
    gate_type: GateType,
}

static ROUND_KEYS: Lazy<[[Fr; 4]; 25]> =
    Lazy::new(|| Fr::PERMUTATION_ROUND_KEYS.map(|r| r.map(Fr::from_le_bytes_mod_order)));
static MDS: Lazy<[[Fr; 4]; 4]> =
    Lazy::new(|| Fr::MDS_LE.map(|r| r.map(Fr::from_le_bytes_mod_order)));
const N_MUL_SELECTORS: usize = 2;

impl Gate {
    fn new(gate_type: GateType) -> Self {
        Self { gate_type }
    }

    pub fn q_lc(&self) -> [Fr; GATE_WIDTH] {
        match self.gate_type {
            GateType::Addition => [Fr::one(), Fr::one(), Fr::zero(), Fr::zero()],
            GateType::Equality => [Fr::one(), -Fr::one(), Fr::zero(), Fr::zero()],
            GateType::CondSelect => [Fr::zero(), Fr::one(), Fr::zero(), Fr::zero()],
            GateType::RescueAddConstant(_) => [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero()],
            GateType::RescueAffine(_, i) => MDS[i as usize],
            GateType::MidNode => [Fr::one(), Fr::one(), Fr::one(), -Fr::one()],
            _ => Default::default(),
        }
    }

    pub fn q_hash(&self) -> [Fr; GATE_WIDTH] {
        match self.gate_type {
            GateType::FifthRoot => [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero()],
            GateType::Power5NonLinear(_, i) => MDS[i as usize],
            _ => Default::default(),
        }
    }

    pub fn q_mul(&self) -> [Fr; N_MUL_SELECTORS] {
        match self.gate_type {
            GateType::Multiplication | GateType::Bool => [Fr::one(), Fr::zero()],
            GateType::CondSelect => [-Fr::one(), Fr::one()],
            _ => Default::default(),
        }
    }

    pub fn q_ecc(&self) -> Fr {
        match self.gate_type {
            _ => Default::default(),
        }
    }

    pub fn q_c(&self) -> Fr {
        match self.gate_type {
            GateType::Zero => Fr::zero(),
            GateType::One => Fr::one(),
            GateType::RescueAddConstant(i) => ROUND_KEYS[0][i as usize],
            GateType::RescueAffine(r, i) | GateType::Power5NonLinear(r, i) => {
                ROUND_KEYS[r as usize][i as usize]
            }
            _ => Default::default(),
        }
    }

    pub fn q_o(&self) -> Fr {
        match self.gate_type {
            GateType::Padding => Fr::zero(),
            _ => Fr::one(),
        }
    }
}

impl PlonkCircuit {
    fn conditional_select(
        &mut self,
        b: Variable,
        x_0: Variable,
        x_1: Variable,
    ) -> Result<Variable, PlonkError> {
        let y = if self.witness(b)? == Fr::zero() {
            self.create_variable(self.witness(x_0)?)?
        } else if self.witness(b)? == Fr::one() {
            self.create_variable(self.witness(x_1)?)?
        } else {
            return Err(CircuitError::ParameterError(
                "b in Conditional Selection gate is not a boolean variable".to_string(),
            )
            .into());
        };
        let wire_vars = [b, x_0, b, x_1, y];
        self.insert_gate(&wire_vars, GateType::CondSelect)?;
        Ok(y)
    }

    fn non_zero_gate(&mut self, var: Variable) -> Result<(), PlonkError> {
        let inverse = self.witness(var)?.inverse().unwrap_or_else(Fr::zero);
        let inv_var = self.create_variable(inverse)?;
        let one_var = self.one();
        self.mul_gate(var, inv_var, one_var)
    }

    fn rescue_permutation(
        &mut self,
        input_var: [Variable; STATE_SIZE],
    ) -> Result<[Variable; STATE_SIZE], PlonkError> {
        let mut state_var = self.add_constant_state(&input_var)?;
        for r in 0..ROUNDS * 2 {
            if r % 2 == 0 {
                state_var = self.pow_alpha_inv_state(&state_var)?;
                state_var = self.affine_transform(&state_var, r + 1)?;
            } else {
                state_var = self.non_linear_transform(&state_var, r + 1)?;
            }
        }
        Ok(state_var)
    }

    fn add_constant_state(
        &mut self,
        input_var: &[Variable; STATE_SIZE],
    ) -> Result<[Variable; STATE_SIZE], PlonkError> {
        let vars: Result<Vec<Variable>, PlonkError> = input_var
            .iter()
            .enumerate()
            .map(|(i, &var)| {
                let input_val = self.witness(var).unwrap();
                let output_val = ROUND_KEYS[0][i] + input_val;
                let output_var = self.create_variable(output_val).unwrap();

                self.insert_gate(
                    &[var, self.one(), 0, 0, output_var],
                    GateType::RescueAddConstant(i as u8),
                )?;

                Ok(output_var)
            })
            .collect();
        let vars = vars?;
        Ok([vars[0], vars[1], vars[2], vars[3]])
    }

    fn pow_alpha_inv_state(
        &mut self,
        input_var: &[Variable; STATE_SIZE],
    ) -> Result<[Variable; STATE_SIZE], PlonkError> {
        Ok(input_var.map(|var| self.pow_alpha_inv(var).unwrap()))
    }

    fn affine_transform(
        &mut self,
        input_var: &[Variable; STATE_SIZE],
        r: usize,
    ) -> Result<[Variable; STATE_SIZE], PlonkError> {
        let output_val = MDS
            .iter()
            .zip(ROUND_KEYS[r])
            .map(|(row, k)| {
                row.iter()
                    .zip(input_var)
                    .fold(k, |acc, (&a, &b)| acc + a * self.witness(b).unwrap())
            })
            .collect::<Vec<_>>();

        let mut output_vars = [Variable::default(); STATE_SIZE];
        for (i, output) in output_vars.iter_mut().enumerate().take(STATE_SIZE) {
            *output = self.create_variable(output_val[i])?;
            let wire_vars = &[input_var[0], input_var[1], input_var[2], input_var[3], *output];
            self.insert_gate(wire_vars, GateType::RescueAffine(r as u8, i as u8))?;
        }
        Ok(output_vars)
    }

    fn non_linear_transform(
        &mut self,
        input_var: &[Variable; STATE_SIZE],
        r: usize,
    ) -> Result<[Variable; STATE_SIZE], PlonkError> {
        let output_val = MDS
            .iter()
            .zip(ROUND_KEYS[r])
            .map(|(row, k)| {
                row.iter()
                    .zip(input_var)
                    .fold(k, |acc, (&a, &b)| acc + a * self.witness(b).unwrap().pow([Fr::A]))
            })
            .collect::<Vec<_>>();

        let mut output_vars = [Variable::default(); STATE_SIZE];
        for (i, output) in output_vars.iter_mut().enumerate().take(STATE_SIZE) {
            *output = self.create_variable(output_val[i])?;
            let wire_vars = &[input_var[0], input_var[1], input_var[2], input_var[3], *output];
            self.insert_gate(wire_vars, GateType::Power5NonLinear(r as u8, i as u8))?;
        }

        Ok(output_vars)
    }

    fn pow_alpha_inv(&mut self, input_var: Variable) -> Result<Variable, PlonkError> {
        let input_val = self.witness(input_var)?;

        let output_val = input_val.pow(Fr::A_INV);
        let output_var = self.create_variable(output_val)?;
        assert_eq!(Fr::A, 5);
        let wire_vars = &[output_var, 0, 0, 0, input_var];
        self.insert_gate(wire_vars, GateType::FifthRoot)?;
        Ok(output_var)
    }

    fn add_merkle_path_variable(
        &mut self,
        merkle_path: &MerklePath<Fr>,
    ) -> Result<Vec<MerkleNodeVars>, PlonkError> {
        let nodes = merkle_path
            .nodes
            .iter()
            .map(|node| -> Result<MerkleNodeVars, PlonkError> {
                Ok(MerkleNodeVars {
                    sibling1: self.create_variable(node.sibling1.to_scalar())?,
                    sibling2: self.create_variable(node.sibling2.to_scalar())?,
                    is_left_child: self.create_variable(Fr::from(node.pos == NodePos::Left))?,
                    is_right_child: self.create_variable(Fr::from(node.pos == NodePos::Right))?,
                })
            })
            .collect::<Result<Vec<MerkleNodeVars>, PlonkError>>()?;

        for node in nodes.iter() {
            self.bool_gate(node.is_left_child)?;
            self.bool_gate(node.is_right_child)?;
            let left_plus_right = self.add(node.is_left_child, node.is_right_child)?;
            self.bool_gate(left_plus_right)?;
        }

        Ok(nodes)
    }

    fn compute_merkle_root(
        &mut self,
        uid: Variable,
        elem: Variable,
        path_vars: &[MerkleNodeVars],
    ) -> Result<Variable, PlonkError> {
        let mut cur_label = self.rescue_permutation([self.zero(), uid, elem, self.zero()])?[0];
        for &MerkleNodeVars { sibling1, sibling2, is_left_child, is_right_child } in path_vars {
            let left_node = self.conditional_select(is_left_child, sibling1, cur_label)?;
            let right_node = self.conditional_select(is_right_child, sibling2, cur_label)?;
            let left_plus_right = self.add(left_node, right_node)?;
            let mid_node = {
                let y = self.create_variable(
                    self.witness(cur_label)? + self.witness(sibling1)? + self.witness(sibling2)?
                        - self.witness(left_plus_right)?,
                )?;

                self.insert_gate(
                    &[cur_label, sibling1, sibling2, left_plus_right, y],
                    GateType::MidNode,
                )?;
                y
            };
            self.non_zero_gate(left_node)?;
            cur_label = self.rescue_permutation([left_node, mid_node, right_node, self.zero()])?[0];
        }
        Ok(cur_label)
    }
}

#[derive(Clone)]
pub struct PlonkCircuit {
    pub num_vars: usize,
    pub gates: Vec<Gate>,
    pub wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
    pub pub_input_gate_ids: Vec<GateId>,
    pub witness: Vec<Fr>,
    /// `wire_permutation` and `extended_id_permutation` are removed to save memory.
    pub num_wire_types: usize,
    pub eval_domain: Radix2EvaluationDomain<Fr>,
    var_offset: usize,
}

impl Default for PlonkCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PlonkCircuit {
    pub fn new() -> Self {
        let zero = Fr::zero();
        let one = Fr::one();
        let mut circuit = Self {
            var_offset: 0,
            num_vars: 2,
            witness: vec![zero, one],
            gates: vec![],
            wire_variables: [vec![], vec![], vec![], vec![], vec![], vec![]],
            pub_input_gate_ids: vec![],
            num_wire_types: GATE_WIDTH + 1,
            eval_domain: Radix2EvaluationDomain::new(1).unwrap(),
        };
        circuit.insert_gate(&[0, 0, 0, 0, 0], GateType::Zero).unwrap();
        circuit.insert_gate(&[0, 0, 0, 0, 1], GateType::One).unwrap();
        circuit
    }

    pub fn new_partial(offset: usize) -> Self {
        Self {
            var_offset: offset,
            num_vars: 0,
            witness: vec![],
            gates: vec![],
            wire_variables: [vec![], vec![], vec![], vec![], vec![], vec![]],
            pub_input_gate_ids: vec![],
            num_wire_types: GATE_WIDTH + 1,
            eval_domain: Radix2EvaluationDomain::new(1).unwrap(),
        }
    }

    pub fn merge(&mut self, parts: Vec<Self>) {
        for part in parts {
            self.num_vars += part.num_vars;
            self.witness.extend_from_slice(&part.witness);
            self.gates.extend_from_slice(&part.gates);
            for (wire_variables, part_wire_variables) in
                self.wire_variables.iter_mut().zip(part.wire_variables.iter())
            {
                wire_variables.extend_from_slice(part_wire_variables);
            }
        }
    }

    /// Insert a general (algebraic) gate
    /// * `wire_vars` - wire variables. Each of these variables must be in range
    /// * `gate` - specific gate to be inserted
    /// * `returns` - an error if some verification fails
    pub fn insert_gate(
        &mut self,
        wire_vars: &[Variable; GATE_WIDTH + 1],
        gate_type: GateType,
    ) -> Result<(), PlonkError> {
        self.check_finalize_flag(false)?;

        for (wire_var, wire_variable) in
            wire_vars.iter().zip(self.wire_variables.iter_mut().take(GATE_WIDTH + 1))
        {
            wire_variable.push(*wire_var)
        }

        self.gates.push(Gate::new(gate_type));
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
        if var >= self.num_vars + self.var_offset {
            return Err(VarIndexOutOfBound(var, self.num_vars).into());
        }
        Ok(())
    }
}

impl PlonkCircuit {
    pub fn srs_size(&self) -> Result<usize, PlonkError> {
        // extra 2 degree for masking polynomial to make snark zero-knowledge
        Ok(self.eval_domain_size()? + 2)
    }

    fn eval_domain_size(&self) -> Result<usize, PlonkError> {
        self.check_finalize_flag(true)?;
        Ok(self.eval_domain.size())
    }

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

    pub fn public_input(&self) -> Result<Vec<Fr>, PlonkError> {
        self.pub_input_gate_ids
            .iter()
            .map(|&gate_id| -> Result<Fr, PlonkError> {
                let var = self.wire_variables[GATE_WIDTH][gate_id];
                self.witness(var)
            })
            .collect::<Result<Vec<Fr>, PlonkError>>()
    }

    fn check_circuit_satisfiability(&self, pub_input: &[Fr]) -> Result<(), PlonkError> {
        if pub_input.len() != self.num_inputs() {
            return Err(PubInputLenMismatch(pub_input.len(), self.pub_input_gate_ids.len()).into());
        }
        self.gates
            .par_iter()
            .enumerate()
            .zip(&self.wire_variables[0])
            .zip(&self.wire_variables[1])
            .zip(&self.wire_variables[2])
            .zip(&self.wire_variables[3])
            .zip(&self.wire_variables[4])
            .for_each(|((((((gate_id, gate), &w0), &w1), &w2), &w3), &w4)| {
                let pi = match self.pub_input_gate_ids.iter().position(|&x| x == gate_id) {
                    Some(i) => pub_input[i],
                    None => Fr::zero(),
                };
                // Compute selector values.
                let q_lc = gate.q_lc();
                let q_mul = gate.q_mul();
                let q_hash = gate.q_hash();
                let q_c = gate.q_c();
                let q_o = gate.q_o();
                let q_ecc = gate.q_ecc();

                // Compute the gate output
                let expected_gate_output = pi
                    + q_lc[0] * self.witness[w0]
                    + q_lc[1] * self.witness[w1]
                    + q_lc[2] * self.witness[w2]
                    + q_lc[3] * self.witness[w3]
                    + q_mul[0] * self.witness[w0] * self.witness[w1]
                    + q_mul[1] * self.witness[w2] * self.witness[w3]
                    + q_ecc
                        * self.witness[w0]
                        * self.witness[w1]
                        * self.witness[w2]
                        * self.witness[w3]
                        * self.witness[w4]
                    + q_hash[0] * self.witness[w0].pow([5])
                    + q_hash[1] * self.witness[w1].pow([5])
                    + q_hash[2] * self.witness[w2].pow([5])
                    + q_hash[3] * self.witness[w3].pow([5])
                    + q_c;
                let gate_output = q_o * self.witness[w4];
                assert_eq!(expected_gate_output, gate_output);
            });

        Ok(())
    }

    fn create_variable(&mut self, val: Fr) -> Result<Variable, PlonkError> {
        self.check_finalize_flag(false)?;
        self.witness.push(val);
        self.num_vars += 1;
        // the index is from `0` to `num_vars - 1`
        Ok(self.num_vars - 1 + self.var_offset)
    }

    fn create_public_variable(&mut self, val: Fr) -> Result<Variable, PlonkError> {
        let var = self.create_variable(val)?;
        self.set_variable_public(var)?;
        Ok(var)
    }

    fn set_variable_public(&mut self, var: Variable) -> Result<(), PlonkError> {
        self.check_finalize_flag(false)?;
        self.pub_input_gate_ids.push(self.num_gates());

        // Create an io gate that forces `witness[var] = public_input`.
        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, GateType::Io)?;
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

    fn witness(&self, idx: Variable) -> Result<Fr, PlonkError> {
        self.check_var_bound(idx)?;
        match idx {
            0 => Ok(Fr::zero()),
            1 => Ok(Fr::one()),
            _ => Ok(self.witness[idx - self.var_offset]),
        }
    }

    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, GateType::Addition)?;
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

    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, GateType::Multiplication)?;
        Ok(())
    }

    fn bool_gate(&mut self, a: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;

        let wire_vars = &[a, a, 0, 0, a];
        self.insert_gate(wire_vars, GateType::Bool)?;
        Ok(())
    }

    fn equal_gate(&mut self, a: Variable, b: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;

        let wire_vars = &[a, b, 0, 0, 0];
        self.insert_gate(wire_vars, GateType::Equality)?;
        Ok(())
    }
}

/// Private helper methods
impl PlonkCircuit {
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

    // pad a finalized circuit to match the evaluation domain, prepared for
    // arithmetization.
    fn pad(&mut self) -> Result<(), PlonkError> {
        self.check_finalize_flag(true)?;
        let n = self.eval_domain.size();
        for _ in self.num_gates()..n {
            self.gates.push(Gate::new(GateType::Padding));
        }
        for wire_id in 0..self.num_wire_types() {
            self.wire_variables[wire_id].resize(n, self.zero());
        }
        Ok(())
    }

    // Check whether the circuit is finalized. Return an error if the finalizing
    // status is different from the expected status.
    #[inline]
    fn check_finalize_flag(&self, expect_finalized: bool) -> Result<(), PlonkError> {
        if expect_finalized {
            assert_eq!(self.var_offset, 0);
        }
        if !self.is_finalized() && expect_finalized {
            return Err(UnfinalizedCircuit.into());
        }
        if self.is_finalized() && !expect_finalized {
            return Err(ModifyFinalizedCircuit.into());
        }
        Ok(())
    }

    // `finalize_for_arithmetization` precomputes `wire_permutation` and `extended_id_permutation`,
    // which cost a lot of memory. Instead, we compute them during proof generation.
    // Note that `circuit.pad()` and `circuit.rearrange_gates()` are still needed.
    pub fn finalize_for_arithmetization(&mut self) -> Result<(), PlonkError> {
        if self.is_finalized() {
            return Ok(());
        }
        self.eval_domain =
            Radix2EvaluationDomain::new(self.num_gates()).ok_or(PlonkError::DomainCreationError)?;
        self.pad()?;
        self.rearrange_gates()?;
        Ok(())
    }
}

/// Generate a gigantic circuit (with random, satisfiable wire assignments).
/// We refactored the original code and added support for parallelism.
/// The resulting circuits should be identical, except for `wire_permutation`
/// and `extended_id_permutation`, which are omitted deliberately.
#[fn_timer(format!("Generate circuit with {} constraints and {} variables", CIRCUIT_CONFIG.num_membership_proofs * (157 * CIRCUIT_CONFIG.tree_height as usize + 149), CIRCUIT_CONFIG.num_membership_proofs * (158 * CIRCUIT_CONFIG.tree_height as usize + 150)))]
pub fn generate_circuit<R: Rng>(rng: &mut R) -> Result<PlonkCircuit, PlonkError> {
    let mut builder = FilledMTBuilder::new(CIRCUIT_CONFIG.tree_height).unwrap();
    for _ in 0..CIRCUIT_CONFIG.num_membership_proofs {
        builder.push(Fr::rand(rng));
    }
    let mt = builder.build();
    let root = mt.commitment().root_value.to_scalar();

    let mut circuit = PlonkCircuit::new();
    let root_var = circuit.create_public_variable(root)?;
    let n = circuit.num_vars();
    let parts = (0..CIRCUIT_CONFIG.num_membership_proofs)
        .into_par_iter()
        .map(|uid| {
            let mut circuit = PlonkCircuit::new_partial(
                n + (150 + CIRCUIT_CONFIG.tree_height as usize * 158) * uid,
            );
            let (_, MerkleLeafProof { leaf, path }) = mt.get_leaf(uid as u64).expect_ok().unwrap();
            let uid = circuit.create_variable(Fr::from(uid as u64)).unwrap();
            let elem = circuit.create_variable(leaf.0).unwrap();
            let path_var = circuit.add_merkle_path_variable(&path).unwrap();

            let claimed_root_var = circuit.compute_merkle_root(uid, elem, &path_var).unwrap();

            circuit.equal_gate(root_var, claimed_root_var).unwrap();
            circuit
        })
        .collect::<Vec<_>>();

    circuit.merge(parts);

    assert!(circuit.check_circuit_satisfiability(&[root]).is_ok());
    circuit.finalize_for_arithmetization().unwrap();

    Ok(circuit)
}

pub fn coset_representatives(num_wire_types: usize, coset_size: usize) -> Vec<Fr> {
    let mut k_vec = vec![Fr::one()];
    let mut pow_k_n_set = HashSet::new();
    pow_k_n_set.insert(Fr::one());
    let mut rng = ChaChaRng::from_seed([0u8; 32]);

    for _ in 1..num_wire_types {
        loop {
            let next = Fr::rand(&mut rng);
            let pow_next_n = next.pow([coset_size as u64]);
            if !pow_k_n_set.contains(&pow_next_n) {
                k_vec.push(next);
                pow_k_n_set.insert(pow_next_n);
                break;
            }
        }
    }
    k_vec
}
