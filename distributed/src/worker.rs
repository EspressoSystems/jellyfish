use std::{collections::HashMap, error::Error, fs::File, ops::Mul, sync::Arc};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::msm::VariableBaseMSM;
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain, UVPolynomial,
};
use capnp::{capability::Promise, message::ReaderOptions};
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use futures::{future::join_all, AsyncReadExt};
#[cfg(feature = "gpu")]
use jf_distributed::gpu::{threadpool::Worker, MultiKernel};
use jf_distributed::{
    config::{FftWorkload, NetworkConfig},
    plonk_capnp::{plonk_peer, plonk_slave},
    utils::{deserialize, serialize},
};
use jf_plonk::prelude::Arithmetization;
use rand::rngs::ThreadRng;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};

struct FftTask {
    is_quot: bool,
    is_inv: bool,
    is_coset: bool,

    workloads: Vec<FftWorkload>,
    rows: Vec<Vec<Fr>>,
    cols: Vec<Vec<Fr>>,
}

#[derive(Default)]
struct Selectors {
    a: DensePolynomial<Fr>,
    h: DensePolynomial<Fr>,
    o: DensePolynomial<Fr>,
    m: DensePolynomial<Fr>,
    e: DensePolynomial<Fr>,
}

struct Context {
    #[cfg(feature = "gpu")]
    kernel: MultiKernel,
    #[cfg(feature = "gpu")]
    pool: Worker,
}

struct State {
    rng: ThreadRng,

    ctx: Context,

    me: usize,
    network: NetworkConfig,

    bases: Vec<G1Affine>,
    domain: Radix2EvaluationDomain<Fr>,
    c_domain: Radix2EvaluationDomain<Fr>,
    r_domain: Radix2EvaluationDomain<Fr>,
    quot_domain: Radix2EvaluationDomain<Fr>,
    quot_c_domain: Radix2EvaluationDomain<Fr>,
    quot_r_domain: Radix2EvaluationDomain<Fr>,

    fft_tasks: HashMap<u64, FftTask>,

    beta: Fr,
    gamma: Fr,
    zeta: Fr,
    k: Fr,

    w: DensePolynomial<Fr>,
    w_tmp: DensePolynomial<Fr>,
    q: Selectors,
    t: DensePolynomial<Fr>,
    sigma: DensePolynomial<Fr>,

    w_of_zeta: Fr,
    w_of_zeta_tmp: Fr,
    sigma_of_zeta: Fr,
}

impl Default for State {
    fn default() -> Self {
        Self {
            rng: Default::default(),
            ctx: Context {
                #[cfg(feature = "gpu")]
                kernel: MultiKernel::create(include_bytes!("./gpu/cl/lib.fatbin")),
                #[cfg(feature = "gpu")]
                pool: Worker::new(),
            },
            me: Default::default(),
            network: Default::default(),
            bases: Default::default(),
            domain: Radix2EvaluationDomain::new(1).unwrap(),
            c_domain: Radix2EvaluationDomain::new(1).unwrap(),
            r_domain: Radix2EvaluationDomain::new(1).unwrap(),
            quot_domain: Radix2EvaluationDomain::new(1).unwrap(),
            quot_c_domain: Radix2EvaluationDomain::new(1).unwrap(),
            quot_r_domain: Radix2EvaluationDomain::new(1).unwrap(),
            fft_tasks: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            zeta: Default::default(),
            w: Default::default(),
            w_tmp: Default::default(),
            q: Default::default(),
            t: Default::default(),
            sigma: Default::default(),
            k: Default::default(),
            w_of_zeta: Default::default(),
            w_of_zeta_tmp: Default::default(),
            sigma_of_zeta: Default::default(),
        }
    }
}

#[derive(Clone)]
struct PlonkImpl {
    state: Arc<State>,
}

async fn connect<A: tokio::net::ToSocketAddrs>(
    addr: A,
) -> Result<plonk_peer::Client, Box<dyn Error>> {
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

impl plonk_slave::Server for PlonkImpl {
    fn init(
        &mut self,
        params: plonk_slave::InitParams,
        _: plonk_slave::InitResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();
        let domain_size = p.get_domain_size() as usize;
        let quot_domain_size = p.get_quot_domain_size() as usize;

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let mut bases = vec![];
        p.get_bases().unwrap().iter().for_each(|n| bases.extend_from_slice(n.unwrap()));
        state.bases = deserialize(&bases).to_vec();
        {
            state.domain = Radix2EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let r = 1 << (self.state.domain.log_size_of_group >> 1);
            let c = self.state.domain.size() / r;
            state.r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
            state.c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();
        }
        {
            state.quot_domain = Radix2EvaluationDomain::<Fr>::new(quot_domain_size).unwrap();
            let r = 1 << (self.state.quot_domain.log_size_of_group >> 1);
            let c = self.state.quot_domain.size() / r;
            state.quot_r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
            state.quot_c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();
        }
        Promise::ok(())
    }

    fn var_msm(
        &mut self,
        params: plonk_slave::VarMsmParams,
        mut results: plonk_slave::VarMsmResults,
    ) -> Promise<(), capnp::Error> {
        let mut scalars = vec![];
        let p = params.get().unwrap();

        let workload = p.get_workload().unwrap();

        let start = workload.get_start() as usize;
        let end = workload.get_end() as usize;

        p.get_scalars()
            .unwrap()
            .iter()
            .for_each(|n| scalars.extend_from_slice(deserialize(n.unwrap())));

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        results.get().set_result(serialize(&[Self::msm(
            &mut state.ctx,
            &state.bases[start..end],
            &scalars,
        )]));

        Promise::ok(())
    }

    fn fft_init(
        &mut self,
        params: plonk_slave::FftInitParams,
        _: plonk_slave::FftInitResults,
    ) -> Promise<(), capnp::Error> {
        let params = params.get().unwrap();

        let id = params.get_id();
        let workloads = params
            .get_workloads()
            .unwrap()
            .into_iter()
            .map(|i| FftWorkload {
                row_start: i.get_row_start() as usize,
                row_end: i.get_row_end() as usize,
                col_start: i.get_col_start() as usize,
                col_end: i.get_col_end() as usize,
            })
            .collect::<Vec<_>>();
        let is_quot = params.get_is_quot();
        let is_inv = params.get_is_inv();
        let is_coset = params.get_is_coset();

        let r_domain = if is_quot { &self.state.quot_r_domain } else { &self.state.r_domain };

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        state.fft_tasks.insert(
            id,
            FftTask {
                is_coset,
                is_inv,
                is_quot,
                rows: vec![vec![]; workloads[self.state.me].num_rows()],
                cols: vec![
                    vec![Fr::default(); r_domain.size()];
                    workloads[self.state.me].num_cols()
                ],
                workloads,
            },
        );

        Promise::ok(())
    }

    fn fft1(
        &mut self,
        params: plonk_slave::Fft1Params,
        _: plonk_slave::Fft1Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let mut v = vec![];

        p.get_v().unwrap().iter().for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));

        let i = p.get_i();
        let id = p.get_id();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let task = state.fft_tasks.get_mut(&id).unwrap();
        let workload = &task.workloads[state.me];

        let (domain, c_domain, r_domain) = if task.is_quot {
            (&self.state.quot_domain, &self.state.quot_c_domain, &self.state.quot_r_domain)
        } else {
            (&self.state.domain, &self.state.c_domain, &self.state.r_domain)
        };

        if task.is_coset && !task.is_inv {
            let g = Fr::multiplicative_generator();
            v.iter_mut().enumerate().for_each(|(j, u)| {
                *u *= g.pow([(i + workload.row_start as u64) + j as u64 * r_domain.size])
            });
        }
        if task.is_inv {
            Self::ifft(&mut state.ctx, c_domain, &mut v);
        } else {
            Self::fft(&mut state.ctx, c_domain, &mut v);
        }
        let omega_shift = if task.is_inv { &domain.group_gen_inv } else { &domain.group_gen };
        v.iter_mut()
            .enumerate()
            .for_each(|(j, u)| *u *= omega_shift.pow([(i + workload.row_start as u64) * j as u64]));

        task.rows[i as usize] = v;

        Promise::ok(())
    }

    fn fft2_prepare(
        &mut self,
        params: plonk_slave::Fft2PrepareParams,
        _: plonk_slave::Fft2PrepareResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();
        let id = p.get_id();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let task = state.fft_tasks.get_mut(&id).unwrap();
        let network = &state.network;
        let me = state.me as u64;

        Promise::from_future(async move {
            let rows = &task.rows;
            let workloads = &task.workloads;

            join_all(network.peers.iter().zip(workloads).map(|(peer, workload)| async move {
                let connection = connect(peer).await.unwrap();

                let mut request = connection.fft_exchange_request();
                let mut r = request.get();
                r.set_id(id);
                r.set_from(me);
                let v = rows
                    .iter()
                    .flat_map(|i| i[workload.col_start..workload.col_end].to_vec())
                    .collect::<Vec<_>>();
                let v_chunks = serialize(&v).chunks(1 << 28);
                let mut builder = r.init_v(v_chunks.len() as u32);
                for (i, chunk) in v_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                request.send().promise.await.unwrap()
            }))
            .await;

            task.rows = vec![];
            Ok(())
        })
    }

    fn fft2(
        &mut self,
        params: plonk_slave::Fft2Params,
        mut results: plonk_slave::Fft2Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let id = p.get_id();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let task = state.fft_tasks.get_mut(&id).unwrap();
        let workload = &task.workloads[state.me];

        let (c_domain, r_domain) = if task.is_quot {
            (&self.state.quot_c_domain, &self.state.quot_r_domain)
        } else {
            (&self.state.c_domain, &self.state.r_domain)
        };

        let mut builder = results.get().init_v(task.cols.len() as u32);
        for (i, chunk) in task.cols.iter_mut().enumerate() {
            let v = chunk;
            let is_inv = task.is_inv;
            let is_coset = task.is_coset;
            if is_inv {
                Self::ifft(&mut state.ctx, r_domain, v);
            } else {
                Self::fft(&mut state.ctx, r_domain, v);
            }
            if is_coset && is_inv {
                let g = Fr::multiplicative_generator().inverse().unwrap();
                v.iter_mut().enumerate().for_each(|(j, u)| {
                    *u *= g.pow([(i + workload.col_start) as u64 + j as u64 * c_domain.size])
                });
            }
            builder.set(i as u32, serialize(v));
        }

        state.fft_tasks.remove(&id);

        Promise::ok(())
    }

    fn round1(
        &mut self,
        params: plonk_slave::Round1Params,
        mut results: plonk_slave::Round1Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        let mut evals = vec![];
        p.get_w().unwrap().iter().for_each(|n| evals.extend_from_slice(deserialize(n.unwrap())));

        Self::ifft(&mut state.ctx, &state.domain, &mut evals);

        state.w = DensePolynomial::rand(1, &mut state.rng).mul_by_vanishing_poly(state.domain)
            + DensePolynomial::from_coefficients_vec(evals);

        results.get().set_c(serialize(&[Self::commit_polynomial(
            &mut state.ctx,
            &state.bases,
            &state.w,
        )]));

        Promise::ok(())
    }

    fn round3_step1_a_h(
        &mut self,
        params: plonk_slave::Round3Step1AHParams,
        mut results: plonk_slave::Round3Step1AHResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me < 4);

        let p = params.get().unwrap();

            let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
            let mut q_a = vec![];
            p.get_q_a().unwrap().iter().for_each(|n| {
                q_a.extend_from_slice(deserialize(n.unwrap()));
            });
            let mut q_h = vec![];
            p.get_q_h().unwrap().iter().for_each(|n| {
                q_h.extend_from_slice(deserialize(n.unwrap()));
            });

        state.q.a = DensePolynomial::from_coefficients_vec(q_a);
        state.q.h = DensePolynomial::from_coefficients_vec(q_h);

        let tmp_domain = Radix2EvaluationDomain::<Fr>::new((state.domain.size() + 2) * 5).unwrap();

        let v = (&state.q.a
            + &state.q.h.mul(&{
                let mut evals = state.w.coeffs.clone();
                Self::fft(&mut state.ctx, &tmp_domain, &mut evals);
                evals.par_iter_mut().for_each(|x| {
                    x.square_in_place();
                    x.square_in_place();
                });
                Self::ifft(&mut state.ctx, &tmp_domain, &mut evals);
                DensePolynomial::from_coefficients_vec(evals)
            }))
            .mul(&state.w);

        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = results.get().init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round3_step1_o(
        &mut self,
        params: plonk_slave::Round3Step1OParams,
        mut results: plonk_slave::Round3Step1OResults,
    ) -> Promise<(), capnp::Error> {
        assert_eq!(self.state.me, 4);

        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let mut q_o = vec![];
        p.get_q_o().unwrap().iter().for_each(|n| {
            q_o.extend_from_slice(deserialize(n.unwrap()));
        });

        state.q.o = DensePolynomial::from_coefficients_vec(q_o);

        let v = -state.q.o.mul(&state.w);

        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = results.get().init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round3_step2_init(
        &mut self,
        _: plonk_slave::Round3Step2InitParams,
        _: plonk_slave::Round3Step2InitResults,
    ) -> Promise<(), capnp::Error> {
        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        match state.me {
            0 | 2 => Promise::from_future(async move {
                let connection = connect(state.network.peers[state.me + 1]).await.unwrap();

                let mut request = connection.round3_step2_m_exchange_request();

                let w_chunks = serialize(&state.w).chunks(1 << 28);
                let mut builder = request.get().init_w(w_chunks.len() as u32);
                for (i, chunk) in w_chunks.enumerate() {
                    builder.set(i as u32, chunk);
                }

                request.send().promise.await.unwrap();
                Ok(())
            }),
            4 => {
                state.w_tmp = state.w.clone();
                Promise::ok(())
            }
            _ => Promise::err(capnp::Error::failed("Invalid slave".to_string())),
        }
    }

    fn round3_step2_m_retrieve(
        &mut self,
        params: plonk_slave::Round3Step2MRetrieveParams,
        mut results: plonk_slave::Round3Step2MRetrieveResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 1 || self.state.me == 3);
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let mut q_m = vec![];
        p.get_q_m().unwrap().iter().for_each(|n| q_m.extend_from_slice(deserialize(n.unwrap())));

        // state.q.m = DensePolynomial::from_coefficients_vec(q_m);

        let v = DensePolynomial::from_coefficients_vec(q_m).mul(&state.w_tmp);
        state.w_tmp = Default::default();

        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = results.get().init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round3_step2_e_retrieve(
        &mut self,
        params: plonk_slave::Round3Step2ERetrieveParams,
        mut results: plonk_slave::Round3Step2ERetrieveResults,
    ) -> Promise<(), capnp::Error> {
        assert_eq!(self.state.me, 4);
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let mut q_e = vec![];
        p.get_q_e().unwrap().iter().for_each(|n| q_e.extend_from_slice(deserialize(n.unwrap())));

        // state.q.e = DensePolynomial::from_coefficients_vec(q_e);

        let v = DensePolynomial::from_coefficients_vec(q_e).mul(&state.w_tmp);
        state.w_tmp = Default::default();

        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = results.get().init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round3_step3(
        &mut self,
        params: plonk_slave::Round3Step3Params,
        mut results: plonk_slave::Round3Step3Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        state.beta = deserialize(p.get_beta().unwrap())[0];
        state.gamma = deserialize(p.get_gamma().unwrap())[0];
        state.k = deserialize(p.get_k().unwrap())[0];

        let v = &state.w + &DensePolynomial { coeffs: vec![state.gamma, state.beta * state.k] };

        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = results.get().init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round3_step4(
        &mut self,
        params: plonk_slave::Round3Step4Params,
        mut results: plonk_slave::Round3Step4Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        let mut sigma = vec![];
        p.get_sigma()
            .unwrap()
            .iter()
            .for_each(|n| sigma.extend_from_slice(deserialize(n.unwrap())));
        state.sigma = DensePolynomial::from_coefficients_vec(sigma);

        let v =
            &state.w + &state.sigma.mul(state.beta) + DensePolynomial { coeffs: vec![state.gamma] };

        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = results.get().init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round3_step5(
        &mut self,
        params: plonk_slave::Round3Step5Params,
        mut results: plonk_slave::Round3Step5Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        let mut t = vec![];
        p.get_t().unwrap().iter().for_each(|n| t.extend_from_slice(deserialize(n.unwrap())));

        state.t = DensePolynomial::from_coefficients_vec(t);

        results.get().set_c(serialize(&[Self::commit_polynomial(
            &mut state.ctx,
            &state.bases,
            &state.t,
        )]));

        Promise::ok(())
    }

    fn round4(
        &mut self,
        params: plonk_slave::Round4Params,
        mut results: plonk_slave::Round4Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        state.zeta = deserialize(p.get_zeta().unwrap())[0];
        state.w_of_zeta = state.w.evaluate(&state.zeta);
        state.sigma_of_zeta = state.sigma.evaluate(&state.zeta);

        let mut r = results.get();

        r.set_v1(serialize(&[state.w_of_zeta]));
        r.set_v2(serialize(&[state.sigma_of_zeta]));

        Promise::ok(())
    }

    fn round5_step1(
        &mut self,
        _: plonk_slave::Round5Step1Params,
        mut results: plonk_slave::Round5Step1Results,
    ) -> Promise<(), capnp::Error> {
        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        let z = -(state.zeta.pow(&[state.domain.size]) - Fr::one())
            * state.zeta.pow(&[(state.domain.size + 2) * state.me as u64]);

        let v1 = if state.me == 4 {
            -state.q.o.mul(state.w_of_zeta)
        } else {
            state.q.a.mul(state.w_of_zeta)
                + state.q.h.mul(state.w_of_zeta * state.w_of_zeta.square().square())
        } + state.t.mul(z);

        let v2 = state.w_of_zeta + state.beta * state.k * state.zeta + state.gamma;
        let v3 = state.w_of_zeta + state.beta * state.sigma_of_zeta + state.gamma;

        let mut r = results.get();
        r.set_v2(serialize(&[v2]));
        r.set_v3(serialize(&[v3]));
        let v1_chunks = serialize(&v1).chunks(1 << 28);
        let mut builder = r.init_v1(v1_chunks.len() as u32);
        for (i, chunk) in v1_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }

    fn round5_step2_init(
        &mut self,
        _: plonk_slave::Round5Step2InitParams,
        _: plonk_slave::Round5Step2InitResults,
    ) -> Promise<(), capnp::Error> {
        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        match state.me {
            0 | 2 => Promise::from_future(async move {
                let connection = connect(state.network.peers[state.me + 1]).await.unwrap();
                let mut request = connection.round5_step2_m_exchange_request();
                request.get().set_w(serialize(&[state.w_of_zeta]));
                request.send().promise.await.unwrap();
                Ok(())
            }),
            4 => {
                state.w_of_zeta_tmp = state.w_of_zeta.clone();
                Promise::ok(())
            }
            _ => Promise::err(capnp::Error::failed("Invalid slave".to_string())),
        }
    }

    fn round5_step2_m_retrieve(
        &mut self,
        _: plonk_slave::Round5Step2MRetrieveParams,
        mut results: plonk_slave::Round5Step2MRetrieveResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 1 || self.state.me == 3);

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        // let v = state.q.m.mul(state.w_of_zeta_tmp);

        // let v_chunks = serialize(&v).chunks(1 << 28);
        // let mut builder = results.get().init_v(v_chunks.len() as u32);
        // for (i, chunk) in v_chunks.enumerate() {
        //     builder.set(i as u32, chunk);
        // }
        results.get().set_v(serialize(&[state.w_of_zeta_tmp]));

        state.w_of_zeta_tmp = Default::default();

        Promise::ok(())
    }

    fn round5_step2_e_retrieve(
        &mut self,
        _: plonk_slave::Round5Step2ERetrieveParams,
        mut results: plonk_slave::Round5Step2ERetrieveResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 4);

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        // let v = state.q.e.mul(state.w_of_zeta_tmp);

        // let v_chunks = serialize(&v).chunks(1 << 28);
        // let mut builder = results.get().init_v(v_chunks.len() as u32);
        // for (i, chunk) in v_chunks.enumerate() {
        //     builder.set(i as u32, chunk);
        // }
        results.get().set_v(serialize(&[state.w_of_zeta_tmp]));

        state.w_of_zeta_tmp = Default::default();

        Promise::ok(())
    }

    fn round5_step3(
        &mut self,
        params: plonk_slave::Round5Step3Params,
        mut results: plonk_slave::Round5Step3Results,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        let v: Fr = deserialize(p.get_v().unwrap())[0];

        let v = state.w.mul(v.pow(&[state.me as u64 + 1]))
            + if state.me == 4 {
                DensePolynomial::zero()
            } else {
                state.sigma.mul(v.pow(&[state.me as u64 + 6]))
            };

        let r = results.get();
        let v_chunks = serialize(&v).chunks(1 << 28);
        let mut builder = r.init_v(v_chunks.len() as u32);
        for (i, chunk) in v_chunks.enumerate() {
            builder.set(i as u32, chunk);
        }

        Promise::ok(())
    }
}

impl plonk_peer::Server for PlonkImpl {
    fn fft_exchange(
        &mut self,
        params: plonk_peer::FftExchangeParams,
        _: plonk_peer::FftExchangeResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let mut v = vec![];

        p.get_v().unwrap().iter().for_each(|n| v.extend_from_slice(deserialize(n.unwrap())));

        let from = p.get_from() as usize;
        let id = p.get_id();

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };
        let task = state.fft_tasks.get_mut(&id).unwrap();

        let num_cols = task.workloads[state.me].num_cols();
        for i in 0..v.len() {
            task.cols[i % num_cols][task.workloads[from].row_start + i / num_cols] = v[i];
        }

        Promise::ok(())
    }

    fn round3_step2_m_exchange(
        &mut self,
        params: plonk_peer::Round3Step2MExchangeParams,
        _: plonk_peer::Round3Step2MExchangeResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 1 || self.state.me == 3);
        let p = params.get().unwrap();

        let mut w = vec![];
        p.get_w().unwrap().iter().for_each(|n| w.extend_from_slice(deserialize(n.unwrap())));
        let w = DensePolynomial::from_coefficients_vec(w);

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        state.w_tmp = state.w.mul(&w);

        Promise::from_future(async move {
            let connection = connect(state.network.peers[4]).await.unwrap();

            let mut request = connection.round3_step2_e_exchange_request();

            let w_chunks = serialize(&state.w_tmp).chunks(1 << 28);
            let mut builder = request.get().init_w(w_chunks.len() as u32);
            for (i, chunk) in w_chunks.enumerate() {
                builder.set(i as u32, chunk);
            }

            request.send().promise.await.unwrap();
            Ok(())
        })
    }

    fn round3_step2_e_exchange(
        &mut self,
        params: plonk_peer::Round3Step2EExchangeParams,
        _: plonk_peer::Round3Step2EExchangeResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 4);
        let p = params.get().unwrap();

        let mut w = vec![];
        p.get_w().unwrap().iter().for_each(|n| w.extend_from_slice(deserialize(n.unwrap())));
        let w = DensePolynomial::from_coefficients_vec(w);

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        state.w_tmp = state.w_tmp.mul(&w);

        Promise::ok(())
    }

    fn round5_step2_m_exchange(
        &mut self,
        params: plonk_peer::Round5Step2MExchangeParams,
        _: plonk_peer::Round5Step2MExchangeResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 1 || self.state.me == 3);
        let p = params.get().unwrap();

        let w: Fr = deserialize(p.get_w().unwrap())[0];

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        state.w_of_zeta_tmp = state.w_of_zeta.mul(w);

        Promise::from_future(async move {
            let connection = connect(state.network.peers[4]).await.unwrap();

            let mut request = connection.round5_step2_e_exchange_request();
            request.get().set_w(serialize(&[state.w_of_zeta_tmp]));

            request.send().promise.await.unwrap();
            Ok(())
        })
    }

    fn round5_step2_e_exchange(
        &mut self,
        params: plonk_peer::Round5Step2EExchangeParams,
        _: plonk_peer::Round5Step2EExchangeResults,
    ) -> Promise<(), capnp::Error> {
        assert!(self.state.me == 4);
        let p = params.get().unwrap();

        let w: Fr = deserialize(p.get_w().unwrap())[0];

        let state = unsafe { &mut *(Arc::as_ptr(&self.state) as *mut State) };

        state.w_of_zeta_tmp = state.w_of_zeta_tmp.mul(w);

        Promise::ok(())
    }
}

impl PlonkImpl {
    // fn pk_gen<C: Arithmetization<Fr>>(
    //     &mut self,
    //     circuit: &C,
    // ) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>) {
    //     let me = self.state.me;
    //     let circuit = unsafe { &*(circuit as *const _ as *const FakePlonkCircuit<Fr>) };
    //     let domain = circuit.eval_domain;
    //     let n = domain.size();
    //     let logn = domain.log_size_of_group;

    //     let mut selector_evals = vec![vec![Fr::zero(); n]; 13];
    //     for (i, gate) in circuit.gates.iter().enumerate() {
    //         let lc = gate.q_lc();
    //         selector_evals[0][i] = lc[0];
    //         selector_evals[1][i] = lc[1];
    //         selector_evals[2][i] = lc[2];
    //         selector_evals[3][i] = lc[3];
    //         let mul = gate.q_mul();
    //         selector_evals[4][i] = mul[0];
    //         selector_evals[5][i] = mul[1];
    //         let hash = gate.q_hash();
    //         selector_evals[6][i] = hash[0];
    //         selector_evals[7][i] = hash[1];
    //         selector_evals[8][i] = hash[2];
    //         selector_evals[9][i] = hash[3];
    //         selector_evals[10][i] = gate.q_o();
    //         selector_evals[11][i] = gate.q_c();
    //         selector_evals[12][i] = gate.q_ecc();
    //     }
    //     // TODO: clear circuit.gates after this

    //     let selector_polys = selector_evals
    //         .into_par_iter()
    //         .map(|mut v| {
    //             domain.ifft_in_place(&mut v);
    //             DensePolynomial::from_coefficients_vec(v)
    //         })
    //         .collect();

    //     let k = Self::coset_representatives(circuit.num_wire_types, n);
    //     let group_elems = domain.elements().collect::<Vec<_>>();
    //     let mut sigma_eval = vec![Fr::zero(); n];
    //     let mut variable_wire_map: Vec<Option<usize>> = vec![None; circuit.num_vars];
    //     let mut variable_wire_first = vec![0usize; circuit.num_vars];
    //     for (wire_id, variables) in
    //         circuit.wire_variables.iter().take(circuit.num_wire_types).enumerate()
    //     {
    //         for (gate_id, &var) in variables.iter().enumerate() {
    //             match variable_wire_map[var] {
    //                 Some(prev) => {
    //                     let prev_wire_id = prev >> logn;
    //                     let prev_gate_id = prev & (n - 1);
    //                     if prev_wire_id == me {
    //                         sigma_eval[prev_gate_id] = k[wire_id] * group_elems[gate_id];
    //                     }
    //                 }
    //                 None => {
    //                     variable_wire_first[var] = (wire_id << logn) + gate_id;
    //                 }
    //             }
    //             variable_wire_map[var] = Some((wire_id << logn) + gate_id);
    //         }
    //     }
    //     for i in 0..circuit.num_vars {
    //         match variable_wire_map[i] {
    //             Some(prev) => {
    //                 let prev_wire_id = prev >> logn;
    //                 let prev_gate_id = prev & (n - 1);
    //                 if prev_wire_id == me {
    //                     sigma_eval[prev_gate_id] = k[variable_wire_first[i] >> logn] * group_elems[variable_wire_first[i] & (n - 1)];
    //                 }
    //             }
    //             None => {}
    //         }
    //     }

    //     let sigma_poly = {
    //         domain.ifft_in_place(&mut sigma_eval);
    //         DensePolynomial::from_coefficients_vec(sigma_eval)
    //     };

    //     (selector_polys, sigma_poly)
    // }

    #[inline]
    fn fft(ctx: &mut Context, domain: &Radix2EvaluationDomain<Fr>, coeffs: &mut Vec<Fr>) {
        coeffs.resize(domain.size(), Fr::zero());
        #[cfg(feature = "gpu")]
        ctx.kernel.radix_fft(coeffs, &domain.group_gen, domain.log_size_of_group);
        #[cfg(not(feature = "gpu"))]
        domain.fft_in_place(coeffs);
    }

    #[inline]
    fn ifft(ctx: &mut Context, domain: &Radix2EvaluationDomain<Fr>, coeffs: &mut Vec<Fr>) {
        coeffs.resize(domain.size(), Fr::zero());
        #[cfg(feature = "gpu")]
        {
            ctx.kernel.radix_fft(coeffs, &domain.group_gen_inv, domain.log_size_of_group);
            coeffs.iter_mut().for_each(|val| *val *= domain.size_inv);
        }
        #[cfg(not(feature = "gpu"))]
        domain.ifft_in_place(coeffs);
    }

    #[inline]
    fn commit_polynomial(ctx: &mut Context, ck: &[G1Affine], poly: &[Fr]) -> G1Projective {
        let mut plain_coeffs = poly.iter().map(|s| s.into_repr()).collect::<Vec<_>>();

        plain_coeffs.resize(ck.len(), Fr::zero().into_repr());

        Self::msm(ctx, ck, &plain_coeffs)
    }

    #[inline]
    fn msm(ctx: &mut Context, bases: &[G1Affine], exps: &[<Fr as PrimeField>::BigInt]) -> G1Projective {
        #[cfg(feature = "gpu")]
        return ctx.kernel.multiexp(&ctx.pool, bases, exps, 0);
        #[cfg(not(feature = "gpu"))]
        return VariableBaseMSM::multi_scalar_mul(bases, exps);
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("usage: {} <me>", args[0]);
        return Ok(());
    }

    let me = args[1].parse().unwrap();

    let network: NetworkConfig = serde_json::from_reader(File::open("config/network.json")?)?;

    let local = tokio::task::LocalSet::new();

    let state = Arc::new({
        let mut state = State::default();
        state.me = me;
        state.network = network;
        state
    });
    let s = Arc::clone(&state);
    local.spawn_local(async move {
        let listener = tokio::net::TcpListener::bind(s.network.slaves[me]).await.unwrap();

        loop {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let (reader, writer) =
                tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
            let network = twoparty::VatNetwork::new(
                reader,
                writer,
                rpc_twoparty_capnp::Side::Server,
                ReaderOptions { traversal_limit_in_words: Some(usize::MAX), nesting_limit: 64 },
            );

            tokio::task::spawn_local(RpcSystem::new(
                Box::new(network),
                Some(
                    capnp_rpc::new_client::<plonk_slave::Client, _>(PlonkImpl { state: s.clone() })
                        .client,
                ),
            ));
        }
    });
    let s = state.clone();
    local.spawn_local(async move {
        let listener = tokio::net::TcpListener::bind(s.network.peers[me]).await.unwrap();

        loop {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let (reader, writer) =
                tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
            let network = twoparty::VatNetwork::new(
                reader,
                writer,
                rpc_twoparty_capnp::Side::Server,
                ReaderOptions { traversal_limit_in_words: Some(usize::MAX), nesting_limit: 64 },
            );

            tokio::task::spawn_local(RpcSystem::new(
                Box::new(network),
                Some(
                    capnp_rpc::new_client::<plonk_peer::Client, _>(PlonkImpl { state: s.clone() })
                        .client,
                ),
            ));
        }
    });

    local.await;
    Ok(())
}
