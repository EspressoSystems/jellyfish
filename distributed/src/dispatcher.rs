use std::{
    cmp::max,
    error::Error,
    fs::{create_dir_all, File},
};

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly_commit::kzg10::{Commitment, UniversalParams, VerifierKey};
use ark_std::{end_timer, format, rand::RngCore, start_timer, time::Instant};
use capnp::message::ReaderOptions;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use fn_timer::fn_timer;
use futures::{future::join_all, AsyncReadExt};
use jf_plonk::{
    prelude::{PlonkError, Proof, ProofEvaluations, VerifyingKey},
    transcript::{PlonkTranscript, StandardTranscript},
};
use rayon::{
    prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::{
    config::NetworkConfig,
    constants::{CAPNP_CHUNK_SIZE, NUM_WIRE_TYPES},
    gpu::Domain,
    playground2::Indexer,
    plonk_capnp::plonk_worker,
    send_chunks_until_ok, timer,
    utils::{deserialize, serialize},
};

pub async fn connect<A: tokio::net::ToSocketAddrs>(
    addr: A,
) -> Result<plonk_worker::Client, Box<dyn Error>> {
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

pub struct Plonk {}

pub const BIN_PATH: &str = "./data/dispatcher";

impl Plonk {
    #[fn_timer]
    pub fn universal_setup<R: RngCore>(
        max_degree: usize,
        rng: &mut R,
    ) -> UniversalParams<Bls12_381> {
        let beta = Fr::rand(rng);
        let g = G1Projective::rand(rng);
        let h = G2Projective::rand(rng);

        let powers_of_beta = timer!("Compute powers_of_beta", {
            let mut powers_of_beta = vec![Fr::one()];
            let mut cur = beta;
            for _ in 0..max_degree {
                powers_of_beta.push(cur);
                cur *= &beta;
            }
            powers_of_beta
        });

        let powers_of_g = timer!("Compute powers_of_g", { Self::fixed_msm(g, &powers_of_beta) });

        let h = h.into_affine();
        let beta_h = h.mul(beta).into_affine();

        UniversalParams {
            powers_of_g,
            powers_of_gamma_g: Default::default(),
            h,
            beta_h,
            neg_powers_of_h: Default::default(),
            prepared_h: h.into(),
            prepared_beta_h: beta_h.into(),
        }
    }

    #[fn_timer]
    pub async fn key_gen_async(
        workers: &[plonk_worker::Client],
        seed: [u8; 32],
        mut srs: UniversalParams<Bls12_381>,
        num_inputs: usize,
    ) -> VerifyingKey<Bls12_381> {
        let domain_size = srs.powers_of_g.len() - 3;
        assert!(domain_size.is_power_of_two());

        let g = srs.powers_of_g[0];

        join_all(workers.iter().map(|worker| async move {
            worker.key_gen_prepare_request().send().promise.await.unwrap();
        }))
        .await;

        for chunk in serialize(&srs.powers_of_g).chunks(CAPNP_CHUNK_SIZE) {
            join_all(workers.iter().map(|worker| async move {
                send_chunks_until_ok!({
                    let mut request = worker.key_gen_set_ck_request();
                    request.get().set_data(chunk);
                    request.get().set_hash(xxhash_rust::xxh3::xxh3_64(chunk));
                    request
                });
            }))
            .await;
        }
        srs.powers_of_g.clear();
        srs.powers_of_g.shrink_to_fit();
        let c = join_all(workers.iter().map(|worker| async move {
            let mut request = worker.key_gen_commit_request();
            request.get().set_seed(serialize(&seed));
            let reply = request.send().promise.await.unwrap();
            let c_q: Vec<G1Projective> =
                deserialize(reply.get().unwrap().get_c_q().unwrap()).to_vec();
            let c_s: G1Projective = deserialize(reply.get().unwrap().get_c_s().unwrap())[0];

            (c_q, c_s)
        }))
        .await;
        let selector_comms = vec![
            c[0].0[0], c[1].0[0], c[2].0[0], c[3].0[0], c[1].0[2], c[3].0[2], c[0].0[1], c[1].0[1],
            c[2].0[1], c[3].0[1], c[4].0[0], c[4].0[1], c[4].0[2],
        ]
        .into_iter()
        .map(|c| Commitment(c.into()))
        .collect();
        let sigma_comms = c.into_iter().map(|(_, c_s)| Commitment(c_s.into())).collect();
        VerifyingKey {
            domain_size,
            num_inputs,
            sigma_comms,
            selector_comms,
            k: Indexer::coset_representatives(NUM_WIRE_TYPES, domain_size),
            open_key: VerifierKey {
                g,
                gamma_g: Default::default(),
                h: srs.h,
                beta_h: srs.beta_h,
                prepared_h: srs.prepared_h.clone(),
                prepared_beta_h: srs.prepared_beta_h.clone(),
            },
        }
    }

    #[fn_timer]
    async fn prove_round1<T: PlonkTranscript<Fq>>(
        workers: &[plonk_worker::Client],
        transcript: &mut T,
    ) -> Result<Vec<Commitment<Bls12_381>>, PlonkError> {
        let wires_poly_comms = join_all(workers.iter().map(|worker| async move {
            let reply = worker.prove_round1_request().send().promise.await.unwrap();
            let r = reply.get().unwrap().get_c().unwrap();

            Commitment::<Bls12_381>(deserialize::<G1Projective>(r)[0].into())
        }))
        .await;
        transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
        Ok(wires_poly_comms)
    }

    pub async fn prove_async(
        workers: &[plonk_worker::Client],
        pub_inputs: &[Fr],
        vk: &VerifyingKey<Bls12_381>,
    ) -> Result<Proof<Bls12_381>, PlonkError> {
        let domain = Domain::new(vk.domain_size);
        let n = domain.size();

        let mut transcript = <StandardTranscript as PlonkTranscript<Fr>>::new(b"PlonkProof");
        transcript.append_vk_and_pub_input(vk, &pub_inputs)?;

        // Round 1
        let wires_poly_comms = Self::prove_round1(&workers, &mut transcript).await?;
        println!("wires_poly_comms:");
        for i in &wires_poly_comms {
            println!("{}", i.0);
        }

        // Round 2
        let now = Instant::now();
        let beta = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"beta")?;
        let gamma = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"gamma")?;
        join_all(workers.iter().enumerate().map(|(_i, worker)| async move {
            let mut request = worker.prove_round2_compute_request();
            request.get().set_beta(serialize(&[beta]));
            request.get().set_gamma(serialize(&[gamma]));
            request.send().promise.await.unwrap();
        }))
        .await;
        join_all([&workers[0], &workers[2]].map(|worker| async move {
            worker.prove_round2_exchange_request().send().promise.await.unwrap();
        }))
        .await;
        let prod_perm_poly_comm = Commitment(
            deserialize::<G1Projective>(
                workers[4]
                    .prove_round2_commit_request()
                    .send()
                    .promise
                    .await
                    .unwrap()
                    .get()
                    .unwrap()
                    .get_c()
                    .unwrap(),
            )[0]
            .into(),
        );
        println!("prod_perm_poly_comm:");
        println!("{}", prod_perm_poly_comm.0);
        transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 3
        let now = Instant::now();
        let alpha = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"alpha")?;

        join_all(workers.iter().map(|worker| async move {
            let mut request = worker.prove_round3_prepare_request();
            request.get().set_alpha(serialize(&[alpha]));
            request.send().promise.await.unwrap();
        }))
        .await;

        join_all(workers.iter().map(|worker| async move {
            worker.prove_round3_compute_t_part1_type1_request().send().promise.await.unwrap();
        }))
        .await;

        join_all(workers.iter().take(NUM_WIRE_TYPES - 1).map(|worker| async move {
            worker.prove_round3_exchange_t_part1_type1_request().send().promise.await.unwrap();
        }))
        .await;

        join_all([&workers[0], &workers[2]].map(|worker| async move {
            worker.prove_round3_exchange_w1_request().send().promise.await.unwrap();
        }))
        .await;

        workers[4]
            .prove_round3_compute_and_exchange_t_part1_type3_request()
            .send()
            .promise
            .await
            .unwrap();
        workers[4]
            .prove_round3_compute_and_exchange_t_part2_request()
            .send()
            .promise
            .await
            .unwrap();

        join_all([&workers[1], &workers[3]].map(|worker| async move {
            worker
                .prove_round3_compute_and_exchange_t_part1_type2_request()
                .send()
                .promise
                .await
                .unwrap();
        }))
        .await;

        join_all([&workers[0], &workers[2]].map(|worker| async move {
            worker.prove_round3_compute_and_exchange_w3_request().send().promise.await.unwrap();
        }))
        .await;

        workers[4]
            .prove_round3_compute_and_exchange_t_part3_request()
            .send()
            .promise
            .await
            .unwrap();

        let split_quot_poly_comms = join_all(workers.iter().rev().map(|worker| async move {
            Commitment(
                deserialize::<G1Projective>(
                    worker
                        .prove_round3_commit_request()
                        .send()
                        .promise
                        .await
                        .unwrap()
                        .get()
                        .unwrap()
                        .get_c()
                        .unwrap(),
                )[0]
                .into(),
            )
        }))
        .await;
        println!("split_quot_poly_comms:");
        for i in &split_quot_poly_comms {
            println!("{}", i.0);
        }
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 4
        let now = Instant::now();
        let zeta = <StandardTranscript as PlonkTranscript<Fr>>::get_and_append_challenge::<
            Bls12_381,
        >(&mut transcript, b"zeta")?;
        let wires_evals = join_all(workers.iter().map(|worker| async move {
            let mut request = worker.prove_round4_evaluate_w_request();
            request.get().set_zeta(serialize(&[zeta]));

            let reply = request.send().promise.await.unwrap();
            let r = reply.get().unwrap();
            deserialize::<Fr>(r.get_w().unwrap())[0]
        }))
        .await;
        let mut wire_sigma_evals = join_all(workers.iter().map(|worker| async move {
            let reply =
                worker.prove_round4_evaluate_sigma_or_z_request().send().promise.await.unwrap();
            let r = reply.get().unwrap();
            deserialize::<Fr>(r.get_sigma_or_z().unwrap())[0]
        }))
        .await;
        let perm_next_eval = wire_sigma_evals.pop().unwrap();
        println!("wires_evals:");
        for i in &wires_evals {
            println!("{}", i);
        }
        println!("wire_sigma_evals:");
        for i in &wire_sigma_evals {
            println!("{}", i);
        }
        println!("perm_next_eval:");
        println!("{}", perm_next_eval);
        let poly_evals = ProofEvaluations { wires_evals, wire_sigma_evals, perm_next_eval };

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
        let s1 = alpha * (zeta.pow(&[n as u64]) - Fr::one())
            / (Fr::from(n as u32) * (zeta - Fr::one()))
            + poly_evals.wires_evals.iter().zip(&vk.k).fold(Fr::one(), |acc, (w_of_zeta, k)| {
                acc * (*w_of_zeta + beta * k * zeta + gamma)
            });
        let s2 = poly_evals
            .wires_evals
            .iter()
            .zip(&poly_evals.wire_sigma_evals)
            .fold(-alpha * beta * perm_next_eval, |acc, (w_of_zeta, sigma_of_zeta)| {
                acc * (*w_of_zeta + beta * sigma_of_zeta + gamma)
            });
        join_all(workers.iter().map(|worker| async move {
            let mut request = worker.prove_round5_prepare_request();
            request.get().set_v(serialize(&[v]));
            request.get().set_s1(serialize(&[s1]));
            request.get().set_s2(serialize(&[s2]));
            request.send().promise.await.unwrap();
        }))
        .await;

        join_all([&workers[0], &workers[2]].map(|worker| async move {
            worker.prove_round5_exchange_request().send().promise.await.unwrap();
        }))
        .await;

        let reply = workers[4].prove_round5_commit_request().send().promise.await.unwrap();

        let opening_proof = Commitment(
            deserialize::<G1Projective>(reply.get().unwrap().get_c_t().unwrap())[0].into(),
        );
        let shifted_opening_proof = Commitment(
            deserialize::<G1Projective>(reply.get().unwrap().get_c_z().unwrap())[0].into(),
        );
        println!("opening_proof:");
        println!("{}", opening_proof.0);
        println!("shifted_opening_proof:");
        println!("{}", shifted_opening_proof.0);
        println!("Elapsed: {:.2?}", now.elapsed());

        Ok(Proof {
            wires_poly_comms,
            prod_perm_poly_comm,
            split_quot_poly_comms,
            opening_proof,
            shifted_opening_proof,
            poly_evals,
        })
    }
}

impl Plonk {
    fn fixed_msm(g: G1Projective, v: &[Fr]) -> Vec<G1Affine> {
        assert!(!g.is_zero());
        let num_scalars = v.len();
        let window =
            if num_scalars < 32 { 3 } else { (ark_std::log2(num_scalars) * 69 / 100) as usize + 2 };
        let scalar_size = Fr::size_in_bits();
        let outerc = (scalar_size + window - 1) / window;
        let table = {
            let in_window = 1 << window;
            let last_in_window = 1 << (scalar_size - (outerc - 1) * window);

            let mut g_outer = g;
            let mut g_outers = Vec::with_capacity(outerc);
            for _ in 0..outerc {
                g_outers.push(g_outer);
                for _ in 0..window {
                    g_outer.double_in_place();
                }
            }
            g_outers
                .into_par_iter()
                .enumerate()
                .map(|(outer, g_outer)| {
                    let cur_in_window =
                        if outer == outerc - 1 { last_in_window } else { in_window };

                    let mut multiples_of_g = vec![G1Projective::zero(); in_window];
                    let mut g_inner = G1Projective::zero();
                    for inner in multiples_of_g.iter_mut().take(cur_in_window) {
                        *inner = g_inner;
                        g_inner += &g_outer;
                    }
                    G1Projective::batch_normalization(&mut multiples_of_g);
                    multiples_of_g.into_iter().map(|v| v.into()).collect::<Vec<G1Affine>>()
                })
                .collect::<Vec<_>>()
        };

        v.par_chunks(max(v.len() / rayon::current_num_threads(), 1))
            .flat_map(|v| {
                let mut prod = Vec::with_capacity(v.len());
                let mut tmp = Fq::one();
                let (mut r, z): (Vec<_>, Vec<_>) = v
                    .iter()
                    .map(|e| {
                        assert!(!e.is_zero());
                        let scalar_val = e.into_repr().to_bits_le();

                        let mut res = table[0][0].into_projective();
                        for outer in 0..outerc {
                            let mut inner = 0usize;
                            for i in 0..window {
                                if outer * window + i < scalar_size
                                    && scalar_val[outer * window + i]
                                {
                                    inner |= 1 << i;
                                }
                            }
                            res.add_assign_mixed(&table[outer][inner]);
                        }
                        prod.push(tmp);

                        tmp *= res.z;

                        (G1Affine::new(res.x, res.y, false), res.z)
                    })
                    .unzip();

                // Invert `tmp`.
                tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

                // Second pass: iterate backwards to compute inverses
                for ((z, s), r) in z.into_iter().zip(prod.into_iter()).zip(r.iter_mut()).rev() {
                    let inv = tmp * &s;
                    tmp *= z;
                    let z2 = inv.square();
                    r.x *= z2;
                    r.y *= z2 * inv;
                }
                r
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use jf_plonk::proof_system::{PlonkKzgSnark, Snark};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::{circuit2::generate_circuit, worker::run_worker};

    #[test]
    fn test_plonk() -> Result<(), Box<dyn Error>> {
        let network: NetworkConfig =
            serde_json::from_reader(File::open("config/network.json")?).unwrap();
        assert_eq!(network.workers.len(), NUM_WIRE_TYPES);

        let mut seed = [0; 32];
        thread_rng().fill_bytes(&mut seed);

        let rng = &mut ChaChaRng::from_seed(seed);

        let circuit = generate_circuit(rng).unwrap();
        let srs = Plonk::universal_setup(circuit.srs_size().unwrap(), rng);

        let public_inputs = circuit.public_input().unwrap();

        let handle = thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
                async {
                    run_worker(4).await.unwrap();
                },
            );
        });

        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
            async {
                tokio::task::LocalSet::new()
                    .run_until(async {
                        let workers = join_all(
                            network
                                .workers
                                .iter()
                                .map(|addr| async move { connect(addr).await.unwrap() }),
                        )
                        .await;
                        let vk =
                            Plonk::key_gen_async(&workers, seed, srs, public_inputs.len()).await;

                        for i in &vk.selector_comms {
                            println!("{}", i.0);
                        }
                        for i in &vk.sigma_comms {
                            println!("{}", i.0);
                        }
                        join_all(workers.iter().map(|worker| async move {
                            worker.prove_init_request().send().promise.await.unwrap()
                        }))
                        .await;
                        for _ in 0..20 {
                            let proof =
                                Plonk::prove_async(&workers, &public_inputs, &vk).await.unwrap();
                            assert!(PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(
                                &vk,
                                &public_inputs,
                                &proof
                            )
                            .is_ok());
                        }
                    })
                    .await
            },
        );

        handle.join().unwrap();

        Ok(())
    }
}
