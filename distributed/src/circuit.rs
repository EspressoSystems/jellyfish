use ark_bls12_381::Fr;
use ark_ff::{FftField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use fn_timer::fn_timer;
use jf_plonk::{
    circuit::{
        gates::{Gate, PaddingGate},
        GateId, Variable, WireId,
    },
    constants::GATE_WIDTH,
    prelude::{Circuit, PlonkCircuit, PlonkError},
};
use jf_primitives::{
    circuit::merkle_tree::{AccElemVars, MerkleTreeGadget},
    merkle_tree::{FilledMTBuilder, MerkleLeafProof},
};
use rand::Rng;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::constants::{NUM_MEMBERSHIP_PROOFS, TREE_HEIGHT};

// We wrap `PlonkCircuit` to access its internal fields while keeping the original API intact.
#[derive(Debug, Clone)]
pub struct FakePlonkCircuit<F>
where
    F: FftField,
{
    pub num_vars: usize,
    pub gates: Vec<Box<dyn Gate<F>>>,
    pub wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
    pub pub_input_gate_ids: Vec<GateId>,
    pub witness: Vec<F>,
    _wire_permutation: Vec<(WireId, GateId)>,
    _extended_id_permutation: Vec<F>,
    pub num_wire_types: usize,
    pub eval_domain: Radix2EvaluationDomain<F>,
    _var_offset: usize,
}

pub const NUM_CONSTRAINTS: usize = NUM_MEMBERSHIP_PROOFS * (157 * TREE_HEIGHT as usize + 149);
pub const NUM_VARS: usize = NUM_MEMBERSHIP_PROOFS * (158 * TREE_HEIGHT as usize + 150);

/// Generate a gigantic circuit (with random, satisfiable wire assignments).
/// We refactored the original code and added support for parallelism.
/// The resulting circuits should be identical, except for `wire_permutation`
/// and `extended_id_permutation`, which are omitted deliberately.
#[fn_timer(format!("Generate circuit with {NUM_CONSTRAINTS} constraints and {NUM_VARS} variables"))]
pub fn generate_circuit<R: Rng>(rng: &mut R) -> Result<PlonkCircuit<Fr>, PlonkError> {
    let mut builder = FilledMTBuilder::new(TREE_HEIGHT).unwrap();
    for _ in 0..NUM_MEMBERSHIP_PROOFS {
        builder.push(Fr::rand(rng));
    }
    let mt = builder.build();
    let root = mt.commitment().root_value.to_scalar();

    let mut circuit = PlonkCircuit::new();
    let root_var = circuit.create_public_variable(root)?;
    let n = circuit.num_vars();
    let parts = (0..NUM_MEMBERSHIP_PROOFS)
        .into_par_iter()
        .map(|uid| {
            let mut circuit =
                PlonkCircuit::new_partial(n + (150 + TREE_HEIGHT as usize * 158) * uid);
            let (_, MerkleLeafProof { leaf, path }) = mt.get_leaf(uid as u64).expect_ok().unwrap();
            let acc_elem_var = AccElemVars {
                uid: circuit.create_variable(Fr::from(uid as u64)).unwrap(),
                elem: circuit.create_variable(leaf.0).unwrap(),
            };
            let path_var = circuit.add_merkle_path_variable(&path).unwrap();

            let claimed_root_var = circuit.compute_merkle_root(acc_elem_var, &path_var).unwrap();

            circuit.equal_gate(root_var, claimed_root_var).unwrap();
            circuit
        })
        .collect::<Vec<_>>();

    circuit.merge(parts);

    assert!(circuit.check_circuit_satisfiability(&[root]).is_ok());
    {
        // `circuit.finalize_for_arithmetization()` precomputes `wire_permutation` and `extended_id_permutation`, which cost a lot of memory.
        // Instead, we compute them during proof generation.
        // Note that private methods like `circuit.pad()`, `circuit.rearrange_gates()`, etc. are still needed,
        // so we manually copy-and-paste the internal logic here.
        let circuit = unsafe { &mut *(&circuit as *const _ as *mut FakePlonkCircuit<Fr>) };
        circuit.eval_domain = Radix2EvaluationDomain::new(circuit.gates.len())
            .ok_or(PlonkError::DomainCreationError)?;
        let n = circuit.eval_domain.size();
        circuit.gates.resize(n, Box::new(PaddingGate));
        for i in 0..circuit.num_wire_types {
            circuit.wire_variables[i].resize(n, 0);
        }
        for (gate_id, io_gate_id) in circuit.pub_input_gate_ids.iter_mut().enumerate() {
            if *io_gate_id > gate_id {
                circuit.gates.swap(gate_id, *io_gate_id);
                for i in 0..circuit.num_wire_types {
                    circuit.wire_variables[i].swap(gate_id, *io_gate_id);
                }
                *io_gate_id = gate_id;
            }
        }
    };

    Ok(circuit)
}
