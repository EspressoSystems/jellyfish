// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bn254::{g1::Config as Param254, Bn254, Fq as Fq254, Fr as Fr254};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{UniformRand as _, Zero};
use jf_plonk::{
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_relation::{
    gadgets::{ecc::SWToTEConParam, EmulationConfig},
    Circuit, PlonkCircuit,
};
use jf_utils::test_rng;

const NUM_NODES: usize = 200;

fn gen_emulated_key_aggregation_circuit<E, P>(
    num_nodes: usize,
) -> Result<PlonkCircuit<Fr254>, PlonkError>
where
    E: EmulationConfig<Fr254> + SWToTEConParam,
    P: SWCurveConfig<BaseField = E>,
{
    let mut rng = test_rng();
    let mut points = vec![];
    let mut result = Projective::<P>::zero();
    for _ in 0..num_nodes {
        let p = Projective::<P>::rand(&mut rng);
        result += p;
        points.push(p.into_affine());
    }
    let mut circuit = PlonkCircuit::<Fr254>::new_ultra_plonk(20);
    let mut point_vars = vec![];
    for p in points {
        point_vars.push(circuit.create_emulated_sw_point_variable(p.into())?);
    }
    let neutral = Projective::<P>::zero().into_affine();
    let mut acc_point_var = circuit.create_constant_emulated_sw_point_variable(neutral.into())?;
    let result_var =
        circuit.create_public_emulated_sw_point_variable(result.into_affine().into())?;

    for p in point_vars {
        acc_point_var = circuit.emulated_sw_ecc_add(&acc_point_var, &p, E::from(0u64))?;
    }
    circuit.is_emulated_sw_point_equal(&acc_point_var, &result_var)?;

    circuit.finalize_for_arithmetization()?;
    Ok(circuit)
}

#[cfg(any(test, feature = "test-srs"))]
fn bench_emulated_key_aggregation<E, P>(num_nodes: usize)
where
    E: EmulationConfig<Fr254> + SWToTEConParam,
    P: SWCurveConfig<BaseField = E>,
{
    use ark_std::{end_timer, start_timer};

    let mut rng = test_rng();

    let circuit_time = start_timer!(|| format!("Building circuit for {} nodes ", num_nodes));
    let circuit = gen_emulated_key_aggregation_circuit::<E, P>(num_nodes).unwrap();
    end_timer!(circuit_time);

    println!("Num of gates: {}", circuit.num_gates());

    let max_degree = circuit.num_gates() + 2;
    let srs = PlonkKzgSnark::<Bn254>::universal_setup_for_testing(max_degree, &mut rng).unwrap();

    let (pk, _) = PlonkKzgSnark::<Bn254>::preprocess(&srs, &circuit).unwrap();

    let proof_time = start_timer!(|| format!("Generating proof for {} nodes ", num_nodes));
    let _ =
        PlonkKzgSnark::<Bn254>::prove::<_, _, StandardTranscript>(&mut rng, &circuit, &pk, None)
            .unwrap();
    end_timer!(proof_time);
}

#[cfg(any(test, feature = "test-srs"))]
fn main() {
    bench_emulated_key_aggregation::<Fq254, Param254>(NUM_NODES);
}
