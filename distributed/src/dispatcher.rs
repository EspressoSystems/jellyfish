use std::{
    cmp::{max, min},
    convert::TryInto,
    io,
    mem::size_of,
    net::SocketAddr,
};

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::{Commitment, UniversalParams, VerifierKey};
use ark_std::{end_timer, format, rand::RngCore, start_timer};
use fn_timer::fn_timer;
use futures::future::join_all;
use jf_plonk::{
    prelude::{PlonkError, Proof, ProofEvaluations, VerifyingKey},
    transcript::{PlonkTranscript, StandardTranscript},
};
use rayon::{
    prelude::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::ParallelSlice,
};
use stubborn_io::StubbornTcpStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    join,
};

use crate::{
    circuit::coset_representatives,
    config::{DATA_DIR, IP_NAME_MAP, NUM_WIRE_TYPES, WORKERS},
    gpu::{Domain, FFTDomain},
    polynomial::VecPolynomial,
    storage::SliceStorage,
    timer,
    utils::CastSlice,
    worker::{Method, Status},
};

pub struct Plonk {}

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
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        seed: [u8; 32],
        mut srs: UniversalParams<Bls12_381>,
        num_inputs: usize,
    ) -> VerifyingKey<Bls12_381> {
        let domain_size = srs.powers_of_g.len() - 3;
        assert!(domain_size.is_power_of_two());

        let g = srs.powers_of_g[0];

        join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::KeyGenPrepare as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        for chunk in srs.powers_of_g.cast::<u8>().chunks(1 << 30) {
            join_all(workers.iter_mut().map(|worker| async move {
                loop {
                    worker.write_u8(Method::KeyGenSetCk as u8).await.unwrap();
                    worker.write_u64_le(xxhash_rust::xxh3::xxh3_64(chunk)).await.unwrap();
                    worker.write_u64_le(chunk.len() as u64).await.unwrap();
                    worker.write_all(chunk).await.unwrap();
                    worker.flush().await.unwrap();

                    match worker.read_u8().await.unwrap().try_into().unwrap() {
                        Status::Ok => break,
                        Status::HashMismatch => continue,
                    }
                }
            }))
            .await;
        }
        srs.powers_of_g.clear();
        srs.powers_of_g.shrink_to_fit();
        let c = join_all(workers.iter_mut().enumerate().map(|(i, worker)| async move {
            worker.write_u8(Method::KeyGenCommit as u8).await.unwrap();
            worker.write_all(&seed).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut c_s = [0u8; size_of::<G1Projective>()];
                    worker.read_exact(&mut c_s).await.unwrap();
                    let c_s = c_s.cast::<G1Projective>()[0];
                    let mut c_q = match i {
                        0 | 2 => vec![G1Projective::zero(); 2],
                        1 | 3 | 4 => vec![G1Projective::zero(); 3],
                        _ => unreachable!(),
                    };
                    worker.read_exact(c_q.cast_mut()).await.unwrap();
                    (c_q, c_s)
                }
                _ => panic!(),
            }
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
            k: coset_representatives(NUM_WIRE_TYPES, domain_size),
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
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut T,
    ) -> Result<Vec<Commitment<Bls12_381>>, PlonkError> {
        let wires_poly_comms = join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::ProveRound1 as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut c = [0u8; size_of::<G1Projective>()];
                    worker.read_exact(&mut c).await.unwrap();
                    let c = c.cast::<G1Projective>()[0];
                    Commitment(c.into())
                }
                _ => panic!(),
            }
        }))
        .await;
        transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
        Ok(wires_poly_comms)
    }

    #[fn_timer]
    async fn prove_round2<T: PlonkTranscript<Fq>>(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut T,
    ) -> Result<(Fr, Fr, Commitment<Bls12_381>), PlonkError> {
        let beta = transcript.get_and_append_challenge::<Bls12_381>(b"beta")?;
        let gamma = transcript.get_and_append_challenge::<Bls12_381>(b"gamma")?;
        join_all(workers.iter_mut().enumerate().map(|(_i, worker)| async move {
            worker.write_u8(Method::ProveRound2Compute as u8).await.unwrap();
            worker.write_all([beta, gamma].cast()).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;
        join_all(workers.iter_mut().enumerate().filter(|(i, _)| *i == 0 || *i == 2).map(
            |(_, worker)| async move {
                worker.write_u8(Method::ProveRound2Exchange as u8).await.unwrap();
                worker.flush().await.unwrap();

                match worker.read_u8().await.unwrap().try_into().unwrap() {
                    Status::Ok => {}
                    _ => panic!(),
                }
            },
        ))
        .await;
        let prod_perm_poly_comm = {
            workers[4].write_u8(Method::ProveRound2Commit as u8).await.unwrap();
            workers[4].flush().await.unwrap();

            match workers[4].read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut c = [0u8; size_of::<G1Projective>()];
                    workers[4].read_exact(&mut c).await.unwrap();
                    let c = c.cast::<G1Projective>()[0];
                    Commitment(c.into())
                }
                _ => panic!(),
            }
        };
        transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
        Ok((beta, gamma, prod_perm_poly_comm))
    }

    #[fn_timer]
    async fn prove_round3<T: PlonkTranscript<Fq>>(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut T,
        domain: Domain,
    ) -> Result<(Fr, Vec<Commitment<Bls12_381>>), PlonkError> {
        let n = domain.size();
        let quot_domain = Domain::new(n * 8);

        let alpha = transcript.get_and_append_challenge::<Bls12_381>(b"alpha")?;

        join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::ProveRound3Prepare as u8).await.unwrap();
            worker.write_all([alpha].cast()).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        join_all(workers.iter_mut().enumerate().map(|(i, worker)| async move {
            if i == 4 {
                Self::receive_and_store_poly(
                    worker,
                    Method::ProveRound3GetZ,
                    n + 3,
                    &SliceStorage::new(DATA_DIR.join("dispatcher/z_poly.bin")),
                )
                .await
                .unwrap();
            }
            worker.write_u8(Method::ProveRound3ComputeTPart1Type1 as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        join_all(workers.iter_mut().take(NUM_WIRE_TYPES - 1).map(|worker| async move {
            worker.write_u8(Method::ProveRound3ExchangeTPart1Type1 as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        join_all(workers.iter_mut().enumerate().filter(|&(i, _)| i == 0 || i == 2 || i == 4).map(
            |(i, worker)| async move {
                match i {
                    0 | 2 => {
                        worker.write_u8(Method::ProveRound3ExchangeW1 as u8).await.unwrap();
                        worker.flush().await.unwrap();

                        match worker.read_u8().await.unwrap().try_into().unwrap() {
                            Status::Ok => {}
                            _ => panic!(),
                        }
                    }
                    4 => {
                        worker.write_u8(Method::ProveRound3ComputeW3 as u8).await.unwrap();
                        worker.flush().await.unwrap();

                        match worker.read_u8().await.unwrap().try_into().unwrap() {
                            Status::Ok => {
                                Self::receive_and_store_poly(
                                    worker,
                                    Method::ProveRound3GetW3,
                                    n + 2,
                                    &SliceStorage::new(
                                        DATA_DIR.join(format!("dispatcher/w3_poly_{i}.bin")),
                                    ),
                                )
                                .await
                                .unwrap();
                            }
                            _ => panic!(),
                        }
                    }
                    _ => unreachable!(),
                }
            },
        ))
        .await;

        join!(
            async {
                workers[4]
                    .write_u8(Method::ProveRound3ComputeAndExchangeTPart1Type3AndPart2 as u8)
                    .await
                    .unwrap();
                workers[4].flush().await.unwrap();

                match workers[4].read_u8().await.unwrap().try_into().unwrap() {
                    Status::Ok => {}
                    _ => panic!(),
                }
            },
            async {
                let mut peers = join_all(WORKERS.iter().map(|worker| async move {
                    let stream = StubbornTcpStream::connect(worker).await.unwrap();
                    stream.set_nodelay(true).unwrap();
                    stream
                }))
                .await;

                join_all(peers.iter_mut().take(NUM_WIRE_TYPES - 1).enumerate().map(|(i, peer)| async move {
                    peer.write_u8(Method::ProveRound3ComputeW3 as u8).await.unwrap();
                    peer.flush().await.unwrap();

                    match peer.read_u8().await.unwrap().try_into().unwrap() {
                        Status::Ok => {
                            Self::receive_and_store_poly(
                                peer,
                                Method::ProveRound3GetW3,
                                n + 2,
                                &SliceStorage::new(DATA_DIR.join(format!("dispatcher/w3_poly_{i}.bin"))),
                            )
                            .await
                            .unwrap()
                        }
                        _ => panic!(),
                    }
                }))
                .await;
                let mut w = vec![];
                for i in 0..NUM_WIRE_TYPES {
                    timer!(format!("FFT on (w{0} + β * σ{0} + γ)", i), {
                        let storage =
                            SliceStorage::new(DATA_DIR.join(format!("dispatcher/w3_poly_{i}.bin")));
                        let mut w3 = storage.load().unwrap();
                        quot_domain.fft_io(&mut w3);
                        w.push(storage.store_and_mmap(&w3).unwrap())
                    })
                }
                let mut u = timer!("FFT on -α * z'", {
                    let mut z =
                        SliceStorage::new(DATA_DIR.join("dispatcher/z_poly.bin")).load().unwrap();
                    Radix2EvaluationDomain::distribute_powers_and_mul_by_const(
                        &mut z,
                        domain.generator(),
                        -alpha,
                    );
                    quot_domain.fft_io(&mut z);
                    z
                });
                timer!("Compute evals of -α * z' * Π(wi + β * σi + γ)", {
                    u.par_iter_mut()
                        .zip_eq(w[0].par_iter())
                        .zip_eq(w[1].par_iter())
                        .zip_eq(w[2].par_iter())
                        .zip_eq(w[3].par_iter())
                        .zip_eq(w[4].par_iter())
                        .for_each(|(((((u, w0), w1), w2), w3), w4)| {
                            *u *= w0;
                            *u *= w1;
                            *u *= w2;
                            *u *= w3;
                            *u *= w4;
                        });
                });
                timer!("IFFT on u", {
                    quot_domain.ifft_oi(&mut u);
                });

                u.div_by_vanishing_poly(n);

                assert!(u.len() <= 6 * n + 8, "{} {}", u.len(), 6 * n + 8);

                const CHUNK_SIZE: usize = (1 << 30) / size_of::<Fr>();
                for i in (0..n + 2).step_by(CHUNK_SIZE) {
                    join_all(u[n..].chunks(n + 2).zip(peers.iter_mut().rev()).map(
                        |(t, peer)| async move {
                            if i < t.len() {
                                let chunk = t[i..min(i + CHUNK_SIZE, t.len())].cast();
                                let hash = xxhash_rust::xxh3::xxh3_64(chunk);
                                timer!(
                                    format!(
                                        "Send t[{}..{}] to {}",
                                        i,
                                        min(i + CHUNK_SIZE, t.len()),
                                        IP_NAME_MAP.get(&peer.peer_addr().unwrap().ip()).unwrap()
                                    ),
                                    loop {
                                        peer.write_u8(Method::ProveRound3UpdateT as u8)
                                            .await
                                            .unwrap();
                                        peer.write_u64_le(i as u64).await.unwrap();
                                        peer.write_u64_le(hash).await.unwrap();
                                        peer.write_u64_le(chunk.len() as u64).await.unwrap();
                                        peer.write_all(chunk).await.unwrap();
                                        peer.flush().await.unwrap();

                                        match peer.read_u8().await.unwrap().try_into().unwrap() {
                                            Status::Ok => break,
                                            Status::HashMismatch => continue,
                                        }
                                    }
                                );
                            }
                        },
                    ))
                    .await;
                }
            }
        );

        let split_quot_poly_comms = join_all(workers.iter_mut().rev().map(|worker| async move {
            worker.write_u8(Method::ProveRound3Commit as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut c = [0u8; size_of::<G1Projective>()];
                    worker.read_exact(&mut c).await.unwrap();
                    let c = c.cast::<G1Projective>()[0];
                    Commitment(c.into())
                }
                _ => panic!(),
            }
        }))
        .await;
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;
        Ok((alpha, split_quot_poly_comms))
    }

    #[fn_timer]
    async fn prove_round4<T: PlonkTranscript<Fq>>(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut T,
    ) -> Result<(Fr, ProofEvaluations<Fr>), PlonkError> {
        let zeta = transcript.get_and_append_challenge::<Bls12_381>(b"zeta")?;
        let wires_evals = join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::ProveRound4EvaluateW as u8).await.unwrap();
            worker.write_all([zeta].cast()).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut w = [0u8; size_of::<Fr>()];
                    worker.read_exact(&mut w).await.unwrap();
                    let w = w.cast::<Fr>()[0];
                    w
                }
                _ => panic!(),
            }
        }))
        .await;
        let mut wire_sigma_evals = join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::ProveRound4EvaluateSigmaOrZ as u8).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {
                    let mut w = [0u8; size_of::<Fr>()];
                    worker.read_exact(&mut w).await.unwrap();
                    let w = w.cast::<Fr>()[0];
                    w
                }
                _ => panic!(),
            }
        }))
        .await;
        let perm_next_eval = wire_sigma_evals.pop().unwrap();
        let poly_evals = ProofEvaluations { wires_evals, wire_sigma_evals, perm_next_eval };

        transcript.append_proof_evaluations::<Bls12_381>(&poly_evals)?;
        Ok((zeta, poly_evals))
    }

    #[fn_timer]
    async fn prove_round5<T: PlonkTranscript<Fq>>(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        transcript: &mut T,
        s1: Fr,
        s2: Fr,
    ) -> Result<(Commitment<Bls12_381>, Commitment<Bls12_381>), PlonkError> {
        let v = transcript.get_and_append_challenge::<Bls12_381>(b"v")?;
        join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::ProveRound5Prepare as u8).await.unwrap();
            worker.write_all([v, s1, s2].cast()).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        join_all(workers.iter_mut().enumerate().filter(|(i, _)| *i == 0 || *i == 2).map(
            |(_, worker)| async move {
                worker.write_u8(Method::ProveRound5Exchange as u8).await.unwrap();
                worker.flush().await.unwrap();

                match worker.read_u8().await.unwrap().try_into().unwrap() {
                    Status::Ok => {}
                    _ => panic!(),
                }
            },
        ))
        .await;

        workers[4].write_u8(Method::ProveRound5Commit as u8).await?;
        workers[4].flush().await?;

        match workers[4].read_u8().await?.try_into().unwrap() {
            Status::Ok => {
                let mut c = [0u8; size_of::<G1Projective>() * 2];
                workers[4].read_exact(&mut c).await?;
                let c = c.cast::<G1Projective>();
                Ok((Commitment(c[0].into()), Commitment(c[1].into())))
            }
            _ => panic!(),
        }
    }

    pub async fn prove_async(
        workers: &mut [StubbornTcpStream<&'static SocketAddr>],
        pub_inputs: &[Fr],
        vk: &VerifyingKey<Bls12_381>,
    ) -> Result<Proof<Bls12_381>, PlonkError> {
        let domain = Domain::new(vk.domain_size);
        let n = domain.size();

        let mut transcript = <StandardTranscript as PlonkTranscript<Fr>>::new(b"PlonkProof");
        transcript.append_vk_and_pub_input(vk, pub_inputs)?;

        join_all(workers.iter_mut().map(|worker| async move {
            worker.write_u8(Method::ProveInit as u8).await.unwrap();
            worker.write_u64_le(n as u64).await.unwrap();
            worker.flush().await.unwrap();

            match worker.read_u8().await.unwrap().try_into().unwrap() {
                Status::Ok => {}
                _ => panic!(),
            }
        }))
        .await;

        // Round 1
        let wires_poly_comms = Self::prove_round1(workers, &mut transcript).await?;
        println!("wires_poly_comms:");
        for i in &wires_poly_comms {
            println!("{}", i.0);
        }

        // Round 2
        let (beta, gamma, prod_perm_poly_comm) =
            Self::prove_round2(workers, &mut transcript).await?;
        println!("prod_perm_poly_comm:");
        println!("{}", prod_perm_poly_comm.0);

        // Round 3
        let (alpha, split_quot_poly_comms) =
            Self::prove_round3(workers, &mut transcript, domain).await?;
        println!("split_quot_poly_comms:");
        for i in &split_quot_poly_comms {
            println!("{}", i.0);
        }

        // Round 4
        let (zeta, poly_evals) = Self::prove_round4(workers, &mut transcript).await?;
        println!("wires_evals:");
        for i in &poly_evals.wires_evals {
            println!("{}", i);
        }
        println!("wire_sigma_evals:");
        for i in &poly_evals.wire_sigma_evals {
            println!("{}", i);
        }
        println!("perm_next_eval:");
        println!("{}", poly_evals.perm_next_eval);

        // Round 5
        let s1 = alpha.square() * (zeta.pow([n as u64]) - Fr::one())
            / (Fr::from(n as u32) * (zeta - Fr::one()))
            + poly_evals
                .wires_evals
                .iter()
                .zip(&vk.k)
                .fold(alpha, |acc, (w_of_zeta, k)| acc * (beta * k * zeta + gamma + w_of_zeta));
        let s2 = poly_evals
            .wires_evals
            .iter()
            .zip(&poly_evals.wire_sigma_evals)
            .fold(-alpha * beta * poly_evals.perm_next_eval, |acc, (w_eval, sigma_eval)| {
                acc * (beta * sigma_eval + gamma + w_eval)
            });
        let (opening_proof, shifted_opening_proof) =
            Self::prove_round5(workers, &mut transcript, s1, s2).await?;
        println!("opening_proof:");
        println!("{}", opening_proof.0);
        println!("shifted_opening_proof:");
        println!("{}", shifted_opening_proof.0);

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
    pub async fn receive_and_store_poly(
        peer: &mut StubbornTcpStream<&'static SocketAddr>,
        method: Method,
        length: usize,
        storage: &SliceStorage,
    ) -> io::Result<()> {
        storage.create()?;
        let mut i = 0;
        const CHUNK_SIZE: usize = (1 << 32) / size_of::<Fr>();
        while i < length {
            loop {
                peer.write_u8(method as u8).await?;
                peer.write_u64_le(i as u64).await?;
                peer.write_u64_le(min(i + CHUNK_SIZE, length) as u64).await?;
                peer.flush().await?;

                match peer.read_u8().await?.try_into().unwrap() {
                    Status::Ok => {}
                    _ => panic!(),
                }

                let hash = peer.read_u64_le().await?;
                let mut w_buffer = vec![0u8; min(CHUNK_SIZE, length - i) * size_of::<Fr>()];
                peer.read_exact(&mut w_buffer).await?;

                if xxhash_rust::xxh3::xxh3_64(&w_buffer) == hash {
                    storage.append(&w_buffer)?;
                    break;
                }
            }
            i += CHUNK_SIZE;
        }
        Ok(())
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
                    let inv = tmp * s;
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
    use std::{error::Error, thread, time::Duration};

    use jf_plonk::proof_system::{PlonkKzgSnark, Snark};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::{circuit::generate_circuit, config::WORKERS};

    #[tokio::test]
    async fn test_plonk() -> Result<(), Box<dyn Error>> {
        let mut seed = [0; 32];
        thread_rng().fill_bytes(&mut seed);

        let rng = &mut ChaChaRng::from_seed(seed);

        let circuit = generate_circuit(rng).unwrap();
        let srs = Plonk::universal_setup(circuit.srs_size().unwrap(), rng);

        let public_inputs = circuit.public_input().unwrap();

        let mut workers = join_all(WORKERS.iter().map(|worker| async move {
            let stream = loop {
                match StubbornTcpStream::connect(worker).await {
                    Ok(stream) => break stream,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            };
            stream.set_nodelay(true).unwrap();
            stream
        }))
        .await;
        let vk = Plonk::key_gen_async(&mut workers, seed, srs, public_inputs.len()).await;

        for i in &vk.selector_comms {
            println!("{}", i.0);
        }
        for i in &vk.sigma_comms {
            println!("{}", i.0);
        }
        for _ in 0..20 {
            let proof = Plonk::prove_async(&mut workers, &public_inputs, &vk).await.unwrap();
            assert!(PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(
                &vk,
                &public_inputs,
                &proof
            )
            .is_ok());
        }

        Ok(())
    }
}
