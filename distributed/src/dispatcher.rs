use std::{cmp::min, error::Error, fs::File, ops::AddAssign};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::msm::VariableBaseMSM;
use ark_ff::{FromBytes, PrimeField, ToBytes, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::rand::Rng;
use capnp::message::ReaderOptions;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use futures::{future::join_all, join, AsyncReadExt};
#[cfg(feature = "gpu")]
use jf_distributed::gpu::{threadpool::Worker, MultiKernel};
use jf_distributed::{
    config::{FftWorkload, MsmWorkload, NetworkConfig},
    plonk_capnp::{plonk_peer, plonk_slave},
    transpose::ip_transpose,
    utils::{deserialize, serialize},
};
use jf_primitives::{
    circuit::merkle_tree::{AccElemVars, AccMemberWitnessVar, MerkleNodeVars, MerkleTreeGadget},
    merkle_tree::{AccMemberWitness, FilledMTBuilder, MerkleLeafProof, MerkleTree, NodePos},
};
use jf_rescue::RescueParameter;
use rand::thread_rng;

use ark_bls12_381::Bls12_381;
use ark_ff::{FftField, Field, One};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::kzg10::Commitment;
use ark_std::{
    format,
    ops::Mul,
    rand::{CryptoRng, RngCore},
    time::Instant,
};
use jf_plonk::{
    circuit::{Arithmetization, GateId, Variable, WireId, gates::Gate},
    constants::GATE_WIDTH,
    errors::{CircuitError, SnarkError},
    prelude::{Circuit, PlonkCircuit, PlonkError, Proof, ProofEvaluations, ProvingKey},
    proof_system::{PlonkKzgSnark, Snark},
    transcript::{PlonkTranscript, StandardTranscript},
};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

async fn connect<A: tokio::net::ToSocketAddrs>(
    addr: A,
) -> Result<plonk_slave::Client, Box<dyn Error>> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    let (reader, writer) = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
    let rpc_network = Box::new(twoparty::VatNetwork::new(
        reader,
        writer,
        rpc_twoparty_capnp::Side::Client,
        ReaderOptions { traversal_limit_in_words: Some(usize::MAX), nesting_limit: 64 },
    ));
    let mut rpc_system = RpcSystem::new(rpc_network, None);
    let client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
    tokio::task::spawn_local(rpc_system);
    Ok(client)
}

pub async fn init(
    connection: &plonk_slave::Client,
    bases: &[G1Affine],
    domain_size: usize,
    quot_domain_size: usize,
) -> Result<(), Box<dyn Error>> {
    let mut request = connection.init_request();
    let mut r = request.get();
    r.set_domain_size(domain_size as u64);
    r.set_quot_domain_size(quot_domain_size as u64);
    let bases = serialize(bases);
    let chunks = bases.chunks(1 << 28);
    let mut builder = r.init_bases(chunks.len() as u32);
    for (i, chunk) in chunks.enumerate() {
        builder.set(i as u32, chunk);
    }

    request.send().promise.await?;
    Ok(())
}

pub async fn msm(
    connection: &plonk_slave::Client,
    workload: &MsmWorkload,
    scalars: &[<Fr as PrimeField>::BigInt],
) -> Result<G1Projective, Box<dyn Error>> {
    let mut request = connection.var_msm_request();

    let mut w = request.get().init_workload();
    w.set_start(workload.start as u64);
    w.set_end(workload.end as u64);
    let scalars = serialize(scalars);
    let chunks = scalars.chunks(1 << 28);
    let mut builder = request.get().init_scalars(chunks.len() as u32);
    for (i, chunk) in chunks.enumerate() {
        builder.set(i as u32, chunk);
    }

    let reply = request.send().promise.await?;
    let r = reply.get()?.get_result()?;

    Ok(deserialize(r)[0])
}

pub async fn fft_init(
    connection: &plonk_slave::Client,
    id: u64,
    workloads: &[FftWorkload],
    is_quot: bool,
    is_inv: bool,
    is_coset: bool,
) -> Result<(), Box<dyn Error>> {
    let mut request = connection.fft_init_request();
    let mut r = request.get();
    r.set_id(id);
    r.set_is_coset(is_coset);
    r.set_is_inv(is_inv);
    r.set_is_quot(is_quot);
    let mut w = r.init_workloads(workloads.len() as u32);
    for i in 0..workloads.len() {
        w.reborrow().get(i as u32).set_row_start(workloads[i].row_start as u64);
        w.reborrow().get(i as u32).set_row_end(workloads[i].row_end as u64);
        w.reborrow().get(i as u32).set_col_start(workloads[i].col_start as u64);
        w.reborrow().get(i as u32).set_col_end(workloads[i].col_end as u64);
    }

    request.send().promise.await?;

    Ok(())
}

pub async fn fft1(
    connection: &plonk_slave::Client,
    id: u64,
    i: usize,
    v: &[Fr],
) -> Result<(), Box<dyn Error>> {
    let mut request = connection.fft1_request();
    let mut r = request.get();

    r.set_i(i as u64);
    r.set_id(id);

    let chunks = serialize(v).chunks(1 << 28);
    let mut builder = r.init_v(chunks.len() as u32);
    for (i, chunk) in chunks.enumerate() {
        builder.set(i as u32, chunk);
    }

    request.send().promise.await?;

    Ok(())
}

pub async fn fft2_prepare(connection: &plonk_slave::Client, id: u64) -> Result<(), Box<dyn Error>> {
    let mut request = connection.fft2_prepare_request();
    request.get().set_id(id);

    request.send().promise.await?;

    Ok(())
}

pub async fn fft2(connection: &plonk_slave::Client, id: u64) -> Result<Vec<Fr>, Box<dyn Error>> {
    let mut request = connection.fft2_request();
    request.get().set_id(id);
    let reply = request.send().promise.await?;

    let mut r = vec![];

    reply.get()?.get_v()?.iter().for_each(|n| r.extend_from_slice(deserialize(n.unwrap())));

    Ok(r)
}

#[test]
pub fn test_msm() -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    let network: NetworkConfig = serde_json::from_reader(File::open("config/network.json")?)?;
    let num_slaves = network.slaves.len();

    let rng = &mut thread_rng();

    let l = 1 << 10;

    let mut bases =
        (0..min(l, 1 << 11)).map(|_| G1Projective::rand(rng).into()).collect::<Vec<_>>();

    while bases.len() < l {
        bases.append(&mut bases.clone());
    }

    let exps = (0..l).map(|_| Fr::rand(rng).into_repr()).collect::<Vec<_>>();

    tokio::task::LocalSet::new().block_on(&rt, async move {
        let slaves =
            join_all(network.slaves.iter().map(|addr| async move { connect(addr).await.unwrap() }))
                .await;

        let mut workloads = (0..num_slaves)
            .map(|i| MsmWorkload {
                start: i * exps.len() / num_slaves,
                end: (i + 1) * exps.len() / num_slaves,
            })
            .collect::<Vec<_>>();
        workloads[num_slaves - 1].end = exps.len();
        let bases = &bases;
        let exps = &exps;

        join_all(slaves.iter().map(|slave| async move {
            init(slave, bases, 0, 0).await.unwrap();
        }))
        .await;

        let now = Instant::now();
        let r = join_all(workloads.iter().zip(&slaves).map(|(workload, connection)| async move {
            msm(&connection, &workload, &exps[workload.start..workload.end]).await.unwrap()
        }))
        .await
        .into_iter()
        .reduce(|a, b| a + b)
        .unwrap();
        println!("{:?}", now.elapsed());

        let now = Instant::now();
        let s = VariableBaseMSM::multi_scalar_mul(bases, &exps);
        println!("{:?}", now.elapsed());

        assert_eq!(r, s);

        Ok(())
    })
}

#[tokio::test]
pub async fn test_fft() -> Result<(), Box<dyn Error>> {
    let network: NetworkConfig = serde_json::from_reader(File::open("config/network.json")?)?;
    let num_slaves = network.slaves.len();

    let rng = &mut thread_rng();

    let domain = Radix2EvaluationDomain::<Fr>::new(1 << 11).unwrap();
    let quot_domain = Radix2EvaluationDomain::<Fr>::new(1 << 13).unwrap();

    tokio::task::LocalSet::new()
        .run_until(async move {
            let connections = join_all(
                network.slaves.iter().map(|addr| async move { connect(addr).await.unwrap() }),
            )
            .await;

            join_all(connections.iter().map(|connection| async move {
                init(connection, &[], domain.size(), quot_domain.size()).await.unwrap();
            }))
            .await;

            for is_quot in [false, true] {
                let domain = if is_quot { quot_domain } else { domain };

                let r = 1 << (domain.log_size_of_group >> 1);
                let c = domain.size() / r;

                let mut workloads = (0..num_slaves)
                    .map(|i| FftWorkload {
                        row_start: i * (r / num_slaves),
                        row_end: (i + 1) * (r / num_slaves),
                        col_start: i * (c / num_slaves),
                        col_end: (i + 1) * (c / num_slaves),
                    })
                    .collect::<Vec<_>>();
                workloads[num_slaves - 1].row_end = r;
                workloads[num_slaves - 1].col_end = c;
                let workloads = &workloads;

                let coeffs = (0..domain.size()).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

                for is_inv in [false, true] {
                    for is_coset in [false, true] {
                        let id: u64 = rng.gen();

                        join_all(connections.iter().map(|connection| async move {
                            fft_init(connection, id, workloads, is_quot, is_inv, is_coset)
                                .await
                                .unwrap()
                        }))
                        .await;

                        let mut t = coeffs.clone();
                        let mut w = vec![Default::default(); r];
                        ip_transpose(&mut t, &mut w, c, r);
                        let t = &t;

                        join_all(connections.iter().zip(workloads).map(
                            |(connection, workload)| async move {
                                join_all((workload.row_start..workload.row_end).map(
                                    |j| async move {
                                        fft1(
                                            connection,
                                            id,
                                            j - workload.row_start,
                                            &t[j * c..(j + 1) * c],
                                        )
                                        .await
                                        .unwrap()
                                    },
                                ))
                                .await
                            },
                        ))
                        .await;
                        join_all(connections.iter().map(|connection| async move {
                            fft2_prepare(connection, id).await.unwrap()
                        }))
                        .await;
                        let mut u = vec![];
                        let t =
                            join_all(connections.iter().map(|connection| async move {
                                fft2(connection, id).await.unwrap()
                            }))
                            .await;
                        for i in 0..num_slaves {
                            u.extend_from_slice(&t[i]);
                        }
                        ip_transpose(&mut u, &mut w, c, r);

                        assert_eq!(
                            u,
                            match (is_inv, is_coset) {
                                (true, true) => domain.coset_ifft(&coeffs),
                                (true, false) => domain.ifft(&coeffs),
                                (false, true) => domain.coset_fft(&coeffs),
                                (false, false) => domain.fft(&coeffs),
                            }
                        );
                    }
                }
            }

            Ok(())
        })
        .await
}

fn main() {}

pub struct FakePlonkCircuit<F: FftField> {
    num_vars: usize,
    gates: Vec<Box<dyn Gate<F>>>,
    wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
    pub_input_gate_ids: Vec<GateId>,
    witness: Vec<F>,
    wire_permutation: Vec<(WireId, GateId)>,
    extended_id_permutation: Vec<F>,
    num_wire_types: usize,
    eval_domain: Radix2EvaluationDomain<F>,
    _var_offset: usize,
}

pub struct Plonk {}

struct Context {
    slaves: Vec<plonk_slave::Client>,
    #[cfg(feature = "gpu")]
    kernel: MultiKernel,
    #[cfg(feature = "gpu")]
    pool: Worker,
}

impl Plonk {
    async fn prove_async<C, R>(
        ctx: &mut Context,
        prng: &mut R,
        circuit: &C,
        prove_key: &ProvingKey<'_, Bls12_381>,
    ) -> Result<Proof<Bls12_381>, PlonkError>
    where
        C: Arithmetization<Fr>,
        R: CryptoRng + RngCore,
    {
        // Dirty hack
        let circuit = unsafe {
            let circuit = &mut *(circuit as *const _ as *mut FakePlonkCircuit<Fr>);
            circuit.gates.clear();
            circuit.gates.shrink_to_fit();
            circuit.wire_permutation.clear();
            circuit.wire_permutation.shrink_to_fit();
            circuit.extended_id_permutation.clear();
            circuit.extended_id_permutation.shrink_to_fit();
            &*circuit
        };

        let domain = circuit.eval_domain;
        let n = domain.size();
        let num_wire_types = circuit.num_wire_types;

        let ck = &prove_key.commit_key.powers_of_g;

        if n == 1 {
            return Err(CircuitError::UnfinalizedCircuit.into());
        }
        if n < circuit.gates.len() {
            return Err(SnarkError::ParameterError(format!(
                "Domain size {} should be bigger than number of constraint {}",
                n,
                circuit.gates.len()
            ))
            .into());
        }
        if prove_key.domain_size() != n {
            return Err(SnarkError::ParameterError(format!(
                "proving key domain size {} != expected domain size {}",
                prove_key.domain_size(),
                n
            ))
            .into());
        }
        if circuit.pub_input_gate_ids.len() != prove_key.vk.num_inputs {
            return Err(SnarkError::ParameterError(format!(
                "circuit.num_inputs {} != prove_key.num_inputs {}",
                circuit.pub_input_gate_ids.len(),
                prove_key.vk.num_inputs
            ))
            .into());
        }

        join_all(ctx.slaves.iter().map(|slave| async move {
            init(slave, ck, domain.size(), 0).await.unwrap();
        }))
        .await;

        // Initialize transcript
        let mut transcript = <StandardTranscript as PlonkTranscript<Fr>>::new(b"PlonkProof");
        let mut pub_input = DensePolynomial::from_coefficients_vec(
            circuit
                .pub_input_gate_ids
                .iter()
                .map(|&gate_id| {
                    circuit.witness[circuit.wire_variables[num_wire_types - 1][gate_id]]
                })
                .collect(),
        );

        transcript.append_vk_and_pub_input(&prove_key.vk, &pub_input)?;

        Self::ifft(ctx, &domain, &mut pub_input.coeffs);

        // Round 1
        let now = Instant::now();
        let wires_poly_comms =
            join_all(circuit.wire_variables.iter().take(num_wire_types).zip(&ctx.slaves).map(
                |(wire_vars, slave)| async move {
                    let mut request = slave.round1_request();

                    let wire =
                        wire_vars.iter().map(|&var| circuit.witness[var]).collect::<Vec<_>>();
                    let wire_chunks = serialize(&wire).chunks(1 << 28);
                    let mut builder = request.get().init_w(wire_chunks.len() as u32);
                    for (i, chunk) in wire_chunks.enumerate() {
                        builder.set(i as u32, chunk);
                    }

                    let reply = request.send().promise.await.unwrap();
                    let r = reply.get().unwrap().get_c().unwrap();

                    Commitment::<Bls12_381>(deserialize::<G1Projective>(r)[0].into())
                },
            ))
            .await;
        transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 2
        let now = Instant::now();
        let mut domain_elements = domain.elements().collect::<Vec<_>>();
        domain_elements.push(domain_elements[n - 1] * domain.group_gen);
        domain_elements.push(domain_elements[n] * domain.group_gen);
        domain_elements.push(domain_elements[n + 1] * domain.group_gen);
        let beta = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"beta")?;
        let gamma = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"gamma")?;
        let permutation_poly = {
            let mut variable_wires_map = vec![vec![]; circuit.num_vars];
            for (wire_id, variables) in
                circuit.wire_variables.iter().take(num_wire_types).enumerate()
            {
                for (gate_id, &var) in variables.iter().enumerate() {
                    variable_wires_map[var].push((wire_id, gate_id));
                }
            }
            let mut wire_permutation = vec![(0usize, 0usize); num_wire_types * n];
            for wires_vec in variable_wires_map.iter_mut() {
                // The list of wires that map to the same variable forms a cycle.
                if !wires_vec.is_empty() {
                    // push the first item so that window iterator will visit the last item
                    // paired with the first item, forming a cycle
                    wires_vec.push(wires_vec[0]);
                    for window in wires_vec.windows(2) {
                        wire_permutation[window[0].0 * n + window[0].1] = window[1];
                    }
                    // remove the extra first item pushed at the beginning of the iterator
                    wires_vec.pop();
                }
            }

            let wire_variables = &circuit.wire_variables;
            let witness = &circuit.witness;
            let mut product_vec = (0..(n - 1))
                .into_par_iter()
                .map(|j| {
                    let a = (0..num_wire_types)
                        .into_par_iter()
                        .map(|i| {
                            witness[wire_variables[i][j]]
                                + gamma
                                + beta * prove_key.vk.k[i] * domain_elements[j]
                        })
                        .reduce(|| Fr::one(), Fr::mul);
                    let b = (0..num_wire_types)
                        .into_par_iter()
                        .map(|i| {
                            let (perm_i, perm_j) = wire_permutation[i * n + j];
                            witness[wire_variables[i][j]]
                                + gamma
                                + beta * prove_key.vk.k[perm_i] * domain_elements[perm_j]
                        })
                        .reduce(|| Fr::one(), Fr::mul);
                    a / b
                })
                .collect::<Vec<_>>();
            let mut t = Fr::one();
            for i in 0..(n - 1) {
                (product_vec[i], t) = (t, t * product_vec[i]);
            }
            product_vec.push(t);
            Self::ifft(ctx, &domain, &mut product_vec);
            DensePolynomial::rand(2, prng).mul_by_vanishing_poly(domain)
                + DensePolynomial::from_coefficients_vec(product_vec)
        };
        let prod_perm_poly_comm = Self::commit_polynomial(ctx, ck, &permutation_poly);
        transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 3
        let now = Instant::now();
        let alpha = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"alpha")?;
        let alpha_square_div_n = alpha.square() / Fr::from(n as u64);
        let quotient_poly = {
            let mut f = &pub_input + &prove_key.selectors[11];

            for i in 0..4 {
                let mut request = ctx.slaves[i].round3_step1_a_h_request();

                let q_a_chunks = serialize(&prove_key.selectors[i]).chunks(1 << 28);
                let mut builder = request.get().init_q_a(q_a_chunks.len() as u32);
                for (i, chunk) in q_a_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }
                let q_h_chunks = serialize(&prove_key.selectors[i + 6]).chunks(1 << 28);
                let mut builder = request.get().init_q_h(q_h_chunks.len() as u32);
                for (i, chunk) in q_h_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                let reply = request.send().promise.await.unwrap();
                let mut v = vec![];
                reply
                    .get()
                    .unwrap()
                    .get_v()
                    .unwrap()
                    .iter()
                    .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                f += &DensePolynomial::from_coefficients_vec(v);
            }
            {
                let mut request = ctx.slaves[4].round3_step1_o_request();

                let q_o_chunks = serialize(&prove_key.selectors[10]).chunks(1 << 28);
                let mut builder = request.get().init_q_o(q_o_chunks.len() as u32);
                for (i, chunk) in q_o_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                let reply = request.send().promise.await.unwrap();
                let mut v = vec![];
                reply
                    .get()
                    .unwrap()
                    .get_v()
                    .unwrap()
                    .iter()
                    .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                f += &DensePolynomial::from_coefficients_vec(v);
            }
            join!(
                async { ctx.slaves[0].round3_step2_init_request().send().promise.await.unwrap() },
                async { ctx.slaves[2].round3_step2_init_request().send().promise.await.unwrap() },
                async { ctx.slaves[4].round3_step2_init_request().send().promise.await.unwrap() },
            );
            for i in [1, 3] {
                let mut request = ctx.slaves[i].round3_step2_m_retrieve_request();
                let q_m_chunks = serialize(&prove_key.selectors[4 + (i - 1) / 2]).chunks(1 << 28);
                let mut builder = request.get().init_q_m(q_m_chunks.len() as u32);
                for (i, chunk) in q_m_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                let reply = request.send().promise.await.unwrap();
                let mut v = vec![];
                reply
                    .get()
                    .unwrap()
                    .get_v()
                    .unwrap()
                    .iter()
                    .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                f += &DensePolynomial::from_coefficients_vec(v);
            }
            {
                let mut request = ctx.slaves[4].round3_step2_e_retrieve_request();
                let q_e_chunks = serialize(&prove_key.selectors[12]).chunks(1 << 28);
                let mut builder = request.get().init_q_e(q_e_chunks.len() as u32);
                for (i, chunk) in q_e_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                let reply = request.send().promise.await.unwrap();
                let mut v = vec![];
                reply
                    .get()
                    .unwrap()
                    .get_v()
                    .unwrap()
                    .iter()
                    .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                f += &DensePolynomial::from_coefficients_vec(v);
            }
            {
                let mut g = permutation_poly.mul(alpha);
                for i in 0..5 {
                    let mut request = ctx.slaves[i].round3_step3_request();
                    request.get().set_beta(serialize(&[beta]));
                    request.get().set_gamma(serialize(&[gamma]));
                    request.get().set_k(serialize(&[prove_key.vk.k[i]]));

                    let reply = request.send().promise.await.unwrap();
                    let mut v = vec![];
                    reply
                        .get()
                        .unwrap()
                        .get_v()
                        .unwrap()
                        .iter()
                        .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                    g = g.mul(&DensePolynomial::from_coefficients_vec(v));
                }
                f += &g;
            }
            {
                let mut h = permutation_poly.mul(-alpha);
                for i in 0..h.len() {
                    h[i] *= domain_elements[i];
                }
                for i in 0..5 {
                    let mut request = ctx.slaves[i].round3_step4_request();
                    let sigma_chunks = serialize(&prove_key.sigmas[i]).chunks(1 << 28);
                    let mut builder = request.get().init_sigma(sigma_chunks.len() as u32);
                    for (i, chunk) in sigma_chunks.enumerate() {
                        builder.set(i as u32, chunk);
                    }

                    let reply = request.send().promise.await.unwrap();
                    let mut v = vec![];
                    reply
                        .get()
                        .unwrap()
                        .get_v()
                        .unwrap()
                        .iter()
                        .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                    h = h.mul(&DensePolynomial::from_coefficients_vec(v));
                }
                f += &h;
            }
            ({
                let mut remainder = f;
                let mut quotient = vec![Default::default(); remainder.degree()];

                while !remainder.is_zero() && remainder.degree() >= n {
                    let cur_q_coeff = *remainder.coeffs.last().unwrap();
                    let cur_q_degree = remainder.degree() - n;
                    quotient[cur_q_degree] = cur_q_coeff;

                    remainder[cur_q_degree] += &cur_q_coeff;
                    remainder[cur_q_degree + n] -= &cur_q_coeff;
                    while let Some(true) = remainder.coeffs.last().map(|c| c.is_zero()) {
                        remainder.coeffs.pop();
                    }
                }
                DensePolynomial::from_coefficients_vec(quotient)
            } + {
                let mut r = permutation_poly.mul(alpha_square_div_n);
                r[0] -= alpha_square_div_n;
                let mut t = r.coeffs.pop().unwrap();
                for i in (0..r.len()).rev() {
                    (r[i], t) = (t, r[i] + t);
                }
                r
            })
        };
        let split_quot_polys = {
            let expected_degree = num_wire_types * (n + 1) + 2;
            if quotient_poly.degree() != expected_degree {
                return Err(SnarkError::WrongQuotientPolyDegree(
                    quotient_poly.degree(),
                    expected_degree,
                )
                .into());
            }
            quotient_poly
                .coeffs
                .chunks(n + 2)
                .map(DensePolynomial::from_coefficients_slice)
                .collect::<Vec<_>>()
        };
        let split_quot_poly_comms =
            join_all(split_quot_polys.iter().zip(&ctx.slaves).map(|(poly, slave)| async move {
                let mut request = slave.round3_step5_request();

                let poly_chunks = serialize(&poly).chunks(1 << 28);
                let mut builder = request.get().init_t(poly_chunks.len() as u32);
                for (i, chunk) in poly_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                let reply = request.send().promise.await.unwrap();
                let r = reply.get().unwrap().get_c().unwrap();

                Commitment::<Bls12_381>(deserialize::<G1Projective>(r)[0].into())
            }))
            .await;
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 4
        let now = Instant::now();
        let zeta = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"zeta")?;
        let evals = join_all(ctx.slaves.iter().map(|slave| async move {
            let mut request = slave.round4_request();
            request.get().set_zeta(serialize(&[zeta]));

            let reply = request.send().promise.await.unwrap();
            let r = reply.get().unwrap();
            let v1 = deserialize::<Fr>(r.get_v1().unwrap())[0];
            let v2 = deserialize::<Fr>(r.get_v2().unwrap())[0];

            (v1, v2)
        }))
        .await;
        let wires_evals = evals.iter().map(|(v1, _)| *v1).collect::<Vec<_>>();
        let wire_sigma_evals =
            evals.iter().take(num_wire_types - 1).map(|(_, v2)| *v2).collect::<Vec<_>>();
        let perm_next_eval = permutation_poly.evaluate(&(zeta * domain.group_gen));
        let poly_evals = ProofEvaluations {
            wires_evals: wires_evals.clone(),
            wire_sigma_evals: wire_sigma_evals.clone(),
            perm_next_eval,
        };
        <StandardTranscript as PlonkTranscript<Fr>>::append_proof_evaluations::<Bls12_381>(
            &mut transcript,
            &poly_evals,
        )?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 5
        let now = Instant::now();
        let v = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<Bls12_381>(
            &mut transcript,
            b"v",
        )?;
        let lin_poly = {
            let mut f = prove_key.selectors[11].clone();
            let mut g = alpha;
            let mut h = -alpha * beta * perm_next_eval;
            for i in 0..5 {
                let reply = ctx.slaves[i].round5_step1_request().send().promise.await.unwrap();
                let r = reply.get().unwrap();
                let mut v1 = vec![];
                r.get_v1()
                    .unwrap()
                    .iter()
                    .for_each(|n| v1.extend_from_slice(deserialize(n.unwrap())));
                let v2 = deserialize::<Fr>(r.get_v2().unwrap())[0];
                let v3 = deserialize::<Fr>(r.get_v3().unwrap())[0];
                f += &DensePolynomial::from_coefficients_vec(v1);
                g *= v2;
                if i != 4 {
                    h *= v3;
                }
            }
            join!(
                async { ctx.slaves[0].round5_step2_init_request().send().promise.await.unwrap() },
                async { ctx.slaves[2].round5_step2_init_request().send().promise.await.unwrap() },
                async { ctx.slaves[4].round5_step2_init_request().send().promise.await.unwrap() },
            );
            for i in [1, 3] {
                let reply =
                    ctx.slaves[i].round5_step2_m_retrieve_request().send().promise.await.unwrap();
                let v = deserialize::<Fr>(reply.get().unwrap().get_v().unwrap())[0];

                f += &prove_key.selectors[4 + (i - 1) / 2].mul(v);
            }
            {
                let reply =
                    ctx.slaves[4].round5_step2_e_retrieve_request().send().promise.await.unwrap();
                let v = deserialize::<Fr>(reply.get().unwrap().get_v().unwrap())[0];

                f += &prove_key.selectors[12].mul(v);
            }
            f + permutation_poly.mul(
                g + alpha.square() * (zeta.pow(&[n as u64]) - Fr::one())
                    / (Fr::from(n as u32) * (zeta - Fr::one())),
            ) + prove_key.sigmas[num_wire_types - 1].mul(h)
        };
        let opening_proof = {
            let mut f = lin_poly;
            for i in 0..5 {
                let mut request = ctx.slaves[i].round5_step3_request();
                request.get().set_v(serialize(&[v]));

                let reply = request.send().promise.await.unwrap();
                let mut v = vec![];
                reply
                    .get()
                    .unwrap()
                    .get_v()
                    .unwrap()
                    .iter()
                    .for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));
                f += &DensePolynomial::from_coefficients_vec(v);
            }
            Self::commit_polynomial(ctx, &ck, &{
                let mut opening_poly = f;
                let mut t = opening_poly.coeffs.pop().unwrap();
                for i in (0..opening_poly.len()).rev() {
                    (opening_poly[i], t) = (t, opening_poly[i] + t * zeta);
                }
                opening_poly
            })
        };
        let shifted_opening_proof = {
            Self::commit_polynomial(ctx, &ck, &{
                let mut opening_poly = permutation_poly;
                let mut t = opening_poly.coeffs.pop().unwrap();
                for i in (0..opening_poly.len()).rev() {
                    (opening_poly[i], t) = (t, opening_poly[i] + t * domain.group_gen * zeta);
                }
                opening_poly
            })
        };
        println!("Elapsed: {:.2?}", now.elapsed());

        Ok(Proof {
            wires_poly_comms,
            prod_perm_poly_comm,
            split_quot_poly_comms,
            opening_proof,
            shifted_opening_proof,
            poly_evals: ProofEvaluations { wires_evals, wire_sigma_evals, perm_next_eval },
        })
    }

    pub fn prove<C, R>(
        prng: &mut R,
        circuit: &C,
        prove_key: &ProvingKey<Bls12_381>,
    ) -> Result<Proof<Bls12_381>, PlonkError>
    where
        C: Arithmetization<Fr>,
        R: CryptoRng + RngCore,
    {
        let network: NetworkConfig =
            serde_json::from_reader(File::open("config/network.json")?).unwrap();
        assert_eq!(network.slaves.len(), 5);

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        tokio::task::LocalSet::new().block_on(&rt, async {
            Self::prove_async(
                &mut Context {
                    slaves: join_all(
                        network
                            .slaves
                            .iter()
                            .map(|addr| async move { connect(addr).await.unwrap() }),
                    )
                    .await,
                    #[cfg(feature = "gpu")]
                    kernel: MultiKernel::create(include_bytes!("./gpu/cl/lib.fatbin")),
                    #[cfg(feature = "gpu")]
                    pool: Worker::new(),
                },
                prng,
                circuit,
                prove_key,
            )
            .await
        })
    }
}

impl Plonk {
    #[inline]
    fn ifft(ctx: &mut Context, domain: &Radix2EvaluationDomain<Fr>, coeffs: &mut Vec<Fr>) {
        coeffs.resize(domain.size(), Default::default());
        #[cfg(feature = "gpu")]
        {
            ctx.kernel.radix_fft(coeffs, &domain.group_gen_inv, domain.log_size_of_group);
            coeffs.iter_mut().for_each(|val| *val *= domain.size_inv);
        }
        #[cfg(not(feature = "gpu"))]
        domain.ifft_in_place(coeffs);
    }

    #[inline]
    fn commit_polynomial(ctx: &mut Context, ck: &[G1Affine], poly: &[Fr]) -> Commitment<Bls12_381> {
        let mut plain_coeffs = poly.iter().map(|s| s.into_repr()).collect::<Vec<_>>();

        plain_coeffs.resize(ck.len(), Default::default());

        #[cfg(feature = "gpu")]
        let commitment = ctx.kernel.multiexp(&ctx.pool, ck, &plain_coeffs, 0);
        #[cfg(not(feature = "gpu"))]
        let commitment = VariableBaseMSM::multi_scalar_mul(&ck, &plain_coeffs);

        Commitment(commitment.into())
    }
}

pub const TREE_HEIGHT: u8 = 32;
pub const NUM_MEMBERSHIP_PROOFS: usize = 100;

pub fn generate_circuit<R: Rng>(rng: &mut R) -> Result<PlonkCircuit<Fr>, PlonkError> {
    let mut builder = FilledMTBuilder::new(TREE_HEIGHT).unwrap();
    for _ in 0..NUM_MEMBERSHIP_PROOFS {
        builder.push(Fr::rand(rng));
    }
    let mt = builder.build();
    let root = mt.commitment().root_value.to_scalar();

    // construct circuit constraining membership proof check
    let mut circuit = PlonkCircuit::new();
    // add root as a public input
    let root_var = circuit.create_public_variable(root)?;
    let n = circuit.num_vars();
    let parts = (0..NUM_MEMBERSHIP_PROOFS)
        .into_par_iter()
        .map(|uid| {
            let mut circuit =
                PlonkCircuit::new_partial(n + (150 + TREE_HEIGHT as usize * 158) * uid);
            let (_, MerkleLeafProof { leaf, path }) = mt.get_leaf(uid as u64).expect_ok().unwrap();
            let acc_elem_var = AccElemVars {
                uid: circuit.create_variable(Fr::from(uid as u64))?,
                elem: circuit.create_variable(leaf.0)?,
            };
            let path_var = circuit.add_merkle_path_variable(&path)?;

            let claimed_root_var = circuit.compute_merkle_root(acc_elem_var, &path_var)?;

            circuit.equal_gate(root_var, claimed_root_var)?;
            Ok(circuit)
        })
        .collect::<Result<Vec<_>, PlonkError>>()?;

    circuit.merge(parts);

    // sanity check: the circuit must be satisfied.
    assert!(circuit.check_circuit_satisfiability(&[root]).is_ok());
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}

#[test]
fn test_circuit() {
    let rng = &mut thread_rng();

    let circuit = generate_circuit(rng).unwrap();

    println!("{}", circuit.num_gates());
}

#[test]
fn test_plonk() {
    let rng = &mut thread_rng();

    let circuit = generate_circuit(rng).unwrap();
    let srs =
        PlonkKzgSnark::<Bls12_381>::universal_setup(circuit.srs_size().unwrap(), rng).unwrap();
    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit).unwrap();

    let public_inputs = circuit.public_input().unwrap();

    let proof = Plonk::prove(rng, &circuit, &pk).unwrap();
    assert!(PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(&vk, &public_inputs, &proof)
        .is_ok());
}
