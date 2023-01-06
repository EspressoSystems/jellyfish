use std::{
    convert::TryInto,
    error::Error,
    fs::{create_dir_all, File},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use ark_bls12_381::Fr;
use ark_poly::EvaluationDomain;
use ark_std::end_timer;
use capnp::{capability::Promise, message::ReaderOptions};
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use fn_timer::fn_timer;
use futures::{join, AsyncReadExt};
use once_cell::sync::Lazy;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use stubborn_io::StubbornTcpStream;

use crate::{
    circuit2::{generate_circuit, PlonkCircuit},
    config::NetworkConfig,
    constants::NUM_WIRE_TYPES,
    get_req_chunks,
    gpu::{Domain, FFTDomain},
    plonk_capnp::plonk_worker,
    polynomial::VecPolynomial,
    receive_chunk_until_ok, receive_poly_until_ok, send_chunks_until_ok, set_chunk, set_chunks,
    set_data,
    utils::{deserialize, serialize, MmapConfig},
};

mod keygen;
mod round1;
mod round2;
mod round3;
mod round4;
mod round5;
mod utils;

static WORKERS: Lazy<Vec<SocketAddr>> =
    Lazy::new(|| 
        {
            let network: NetworkConfig = serde_json::from_reader(File::open("config/network.json").unwrap()).unwrap();
            network.workers
        }
    );

enum Selectors {
    Type1 { a: MmapConfig, h: MmapConfig },
    Type2 { a: MmapConfig, h: MmapConfig, m: MmapConfig },
    Type3 { o: MmapConfig, c: MmapConfig, e: MmapConfig },
}

pub struct PlonkImplInner {
    me: usize,
    bin_path: String,
    connections: Vec<plonk_worker::Client>,

    n: usize,

    domain1: Domain,
    domain4: Domain,
    domain8: Domain,

    k: Vec<Fr>,
    q: Selectors,
    sigma: MmapConfig,
    sigma_evals: MmapConfig,
    w: MmapConfig,
    w_evals: MmapConfig,
    x: MmapConfig,
    ck: MmapConfig,
    domain1_elements: MmapConfig,

    z: Vec<Fr>,
}

impl PlonkImplInner {
    fn new(me: usize) -> Self {
        let bin_path = format!("./data/worker{me}");

        create_dir_all(&bin_path).unwrap();

        Self {
            me,
            ck: MmapConfig::new(format!("{}/srs.ck.bin", bin_path)),
            x: MmapConfig::new(format!("{}/circuit.inputs.bin", bin_path)),
            w: MmapConfig::new(format!("{}/circuit.wire.bin", bin_path)),
            w_evals: MmapConfig::new(format!("{}/circuit.wire_evals.bin", bin_path)),
            sigma: MmapConfig::new(format!("{}/pk.sigma.bin", bin_path)),
            sigma_evals: MmapConfig::new(format!("{}/pk.sigma_evals.bin", bin_path)),
            domain1_elements: MmapConfig::new(format!("{}/pk.domain_elements.bin", bin_path)),
            q: match me {
                0 | 2 => Selectors::Type1 {
                    a: MmapConfig::new(format!("{}/pk.q_a.bin", bin_path)),
                    h: MmapConfig::new(format!("{}/pk.q_h.bin", bin_path)),
                },
                1 | 3 => Selectors::Type2 {
                    a: MmapConfig::new(format!("{}/pk.q_a.bin", bin_path)),
                    h: MmapConfig::new(format!("{}/pk.q_h.bin", bin_path)),
                    m: MmapConfig::new(format!("{}/pk.q_m.bin", bin_path)),
                },
                4 => Selectors::Type3 {
                    o: MmapConfig::new(format!("{}/pk.q_o.bin", bin_path)),
                    c: MmapConfig::new(format!("{}/pk.q_c.bin", bin_path)),
                    e: MmapConfig::new(format!("{}/pk.q_e.bin", bin_path)),
                },
                _ => unreachable!(),
            },
            bin_path,
            connections: Default::default(),

            n: 0,

            domain1: Default::default(),
            domain4: Default::default(),
            domain8: Default::default(),

            k: Default::default(),
            z: Default::default(),
        }
    }
}

pub struct PlonkImpl {
    inner: Arc<PlonkImplInner>,

    rng: ChaCha20Rng,

    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    zeta: Fr,

    t: Arc<Mutex<Vec<Fr>>>,

    t_part1_tmp: Arc<Mutex<Vec<Fr>>>,

    z_tmp: Arc<Mutex<Vec<Fr>>>,

    w1_tmp: Vec<Fr>,
    w2_tmp: Vec<Fr>,
    w3_tmp: Vec<Fr>,

    w_of_zeta: Arc<Mutex<Fr>>,
}

async fn connect(
    addr: &'static SocketAddr,
) -> Result<plonk_worker::Client, Box<dyn Error>> {
    let stream = StubbornTcpStream::connect(addr).await?;
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

impl plonk_worker::Server for PlonkImpl {
    #[fn_timer(format!("Worker {}: key_gen_prepare", self.inner.me))]
    fn key_gen_prepare(
        &mut self,
        _: plonk_worker::KeyGenPrepareParams,
        _: plonk_worker::KeyGenPrepareResults,
    ) -> Promise<(), capnp::Error> {
        self.inner.ck.create().unwrap();

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: key_gen_set_ck", self.inner.me))]
    fn key_gen_set_ck(
        &mut self,
        params: plonk_worker::KeyGenSetCkParams,
        _: plonk_worker::KeyGenSetCkResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let s = p.get_data().unwrap();
        if xxhash_rust::xxh3::xxh3_64(s) != p.get_hash() {
            return Promise::err(capnp::Error::failed("hash mismatch".into()));
        }
        self.inner.ck.append(s).unwrap();

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: key_gen_commit", self.inner.me))]
    fn key_gen_commit(
        &mut self,
        params: plonk_worker::KeyGenCommitParams,
        mut results: plonk_worker::KeyGenCommitResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let seed = p.get_seed().unwrap().to_owned();
        self.rng = ChaCha20Rng::from_seed(seed.try_into().unwrap());

        // self.inner.init_ck();

        let PlonkCircuit {
            num_vars,
            gates,
            wire_variables,
            pub_input_gate_ids,
            witness,
            num_wire_types,
            eval_domain,
            ..
        } = generate_circuit(&mut self.rng).unwrap();
        assert_eq!(num_wire_types, NUM_WIRE_TYPES);

        let domain_elements = eval_domain.elements().collect::<Vec<_>>();
        self.inner.init_domains(&domain_elements);
        self.inner.init_k(NUM_WIRE_TYPES);
        if self.inner.me == 4 {
            self.inner.store_public_inputs(
                pub_input_gate_ids
                    .into_par_iter()
                    .map(|gate_id| witness[wire_variables[NUM_WIRE_TYPES - 1][gate_id]])
                    .collect(),
            );
        }
        self.inner.store_w_evals(&wire_variables[self.inner.me], witness);

        set_data!(
            results,
            set_c_s,
            &[self.inner.init_and_commit_sigma(wire_variables, num_vars, domain_elements)]
        );
        set_data!(results, set_c_q, &self.inner.init_and_commit_selectors(gates));

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_init", self.inner.me))]
    fn prove_init(
        &mut self,
        _: plonk_worker::ProveInitParams,
        _: plonk_worker::ProveInitResults,
    ) -> Promise<(), capnp::Error> {
        let this = self.inner.clone();

        if this.n == 0 {
            this.init_domains(&this.domain1_elements.load().unwrap());
            this.init_k(NUM_WIRE_TYPES);
        }

        Promise::from_future(async move {
            this.connect_all().await;
            Ok(())
        })
    }

    #[fn_timer(format!("Worker {}: prove_round1", self.inner.me))]
    fn prove_round1(
        &mut self,
        _: plonk_worker::ProveRound1Params,
        mut results: plonk_worker::ProveRound1Results,
    ) -> Promise<(), capnp::Error> {
        set_data!(results, set_c, &[self.inner.init_and_commit_w(&mut self.rng)]);
        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round2_compute", self.inner.me))]
    fn prove_round2_compute(
        &mut self,
        params: plonk_worker::ProveRound2ComputeParams,
        _: plonk_worker::ProveRound2ComputeResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();
        self.beta = deserialize(p.get_beta().unwrap())[0];
        self.gamma = deserialize(p.get_gamma().unwrap())[0];
        self.t = Default::default();

        let this = self.inner.clone();

        *self.z_tmp.lock().unwrap() = this.compute_z_evals(self.beta, self.gamma);

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round2_exchange", self.inner.me))]
    fn prove_round2_exchange(
        &mut self,
        _: plonk_worker::ProveRound2ExchangeParams,
        _: plonk_worker::ProveRound2ExchangeResults,
    ) -> Promise<(), capnp::Error> {
        let this = self.inner.clone();

        let z = self.z_tmp.clone();

        Promise::from_future(async move {
            let z = z.lock().unwrap();
            send_chunks_until_ok!({
                let mut req = this.connections[this.me + 1].prove_round2_update_z_request();
                set_chunks!(req, init_z, &z);
                req
            });
            Ok(())
        })
    }

    #[fn_timer(format!("Worker {}: prove_round2_commit", self.inner.me))]
    fn prove_round2_commit(
        &mut self,
        _: plonk_worker::ProveRound2CommitParams,
        mut results: plonk_worker::ProveRound2CommitResults,
    ) -> Promise<(), capnp::Error> {
        set_data!(
            results,
            set_c,
            &[self.inner.compute_and_commit_z(&mut self.rng, &mut self.z_tmp.lock().unwrap())]
        );
        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_prepare", self.inner.me))]
    fn prove_round3_prepare(
        &mut self,
        params: plonk_worker::ProveRound3PrepareParams,
        _: plonk_worker::ProveRound3PrepareResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        if self.inner.me == 4 {
            let z = self.z_tmp.lock().unwrap().split_off(0);

            self.alpha = deserialize(p.get_alpha().unwrap())[0];

            *self.t.lock().unwrap() = self.inner.compute_t_part4(&z, self.alpha);

            self.inner.init_z(z);
        } else {
            self.z_tmp = Default::default();
        }

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_compute_t_part1_type1", self.inner.me))]
    fn prove_round3_compute_t_part1_type1(
        &mut self,
        _: plonk_worker::ProveRound3ComputeTPart1Type1Params,
        _: plonk_worker::ProveRound3ComputeTPart1Type1Results,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type1 { .. } | Selectors::Type2 { .. } => {
                self.t_part1_tmp = Arc::new(Mutex::new(self.inner.compute_t_part1_type1()));
            }
            Selectors::Type3 { .. } => {
                self.inner.update_t(
                    &mut self.t.lock().unwrap(),
                    &self.inner.compute_t_part1_type1()[self.inner.n..],
                    0,
                );
            }
        }
        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_exchange_t_part1_type1", self.inner.me))]
    fn prove_round3_exchange_t_part1_type1(
        &mut self,
        _: plonk_worker::ProveRound3ExchangeTPart1Type1Params,
        _: plonk_worker::ProveRound3ExchangeTPart1Type1Results,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type1 { .. } | Selectors::Type2 { .. } => {
                let t = self.t_part1_tmp.clone();
                let this = self.inner.clone();
                Promise::from_future(async move {
                    let mut t = t.lock().unwrap();
                    this.share_t(&t[this.n..]).await;
                    t.clear();
                    t.shrink_to_fit();
                    Ok(())
                })
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer(format!("Worker {}: prove_round3_exchange_w1", self.inner.me))]
    fn prove_round3_exchange_w1(
        &mut self,
        _: plonk_worker::ProveRound3ExchangeW1Params,
        _: plonk_worker::ProveRound3ExchangeW1Results,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type1 { .. } => {
                let this = self.inner.clone();

                Promise::from_future(async move {
                    let w = this.w.load::<Fr>().unwrap();
                    send_chunks_until_ok!({
                        let mut req =
                            this.connections[this.me + 1].prove_round3_update_w1_product_request();
                        set_chunks!(req, init_w1, &w);
                        req
                    });
                    Ok(())
                })
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer(format!("Worker {}: prove_round3_compute_and_exchange_t_part1_type3", self.inner.me))]
    fn prove_round3_compute_and_exchange_t_part1_type3(
        &mut self,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart1Type3Params,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart1Type3Results,
    ) -> Promise<(), capnp::Error> {
        let this = self.inner.clone();

        Promise::from_future(async move {
            let l = this.n * 2 + 3;
            let (w0w1, w2w3) = join!(
                receive_poly_until_ok!(
                    this.connections[1],
                    prove_round3_get_w1_product_request,
                    get_w1,
                    l
                ),
                receive_poly_until_ok!(
                    this.connections[3],
                    prove_round3_get_w1_product_request,
                    get_w1,
                    l
                ),
            );
            let t = this.compute_t_part1_type3(w0w1, w2w3);
            this.share_t(&t[this.n..]).await;
            Ok(())
        })
    }

    #[fn_timer(format!("Worker {}: prove_round3_compute_and_exchange_t_part2", self.inner.me))]
    fn prove_round3_compute_and_exchange_t_part2(
        &mut self,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart2Params,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart2Results,
    ) -> Promise<(), capnp::Error> {
        let this = self.inner.clone();
        let alpha = self.alpha;
        let beta = self.beta;
        let gamma = self.gamma;

        Promise::from_future(async move {
            let l = this.n * 2 + 3;
            let (w0w1, w2w3) = join!(
                receive_poly_until_ok!(
                    this.connections[1],
                    prove_round3_get_w2_product_request,
                    get_w2,
                    l
                ),
                receive_poly_until_ok!(
                    this.connections[3],
                    prove_round3_get_w2_product_request,
                    get_w2,
                    l
                ),
            );
            let t = this.compute_t_part2(w0w1, w2w3, alpha, beta, gamma);
            this.share_t(&t[this.n..]).await;
            Ok(())
        })
    }

    #[fn_timer(format!("Worker {}: prove_round3_compute_and_exchange_t_part1_type2", self.inner.me))]
    fn prove_round3_compute_and_exchange_t_part1_type2(
        &mut self,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart1Type2Params,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart1Type2Results,
    ) -> Promise<(), capnp::Error> {
        let this = self.inner.clone();

        self.w2_tmp = Default::default();
        let ww = self.w1_tmp.split_off(0);
        let t = this.compute_t_part1_type2(ww);
        Promise::from_future(async move {
            this.share_t(&t[this.n..]).await;
            Ok(())
        })
    }

    #[fn_timer(format!("Worker {}: prove_round3_compute_and_exchange_w3", self.inner.me))]
    fn prove_round3_compute_and_exchange_w3(
        &mut self,
        _: plonk_worker::ProveRound3ComputeAndExchangeW3Params,
        _: plonk_worker::ProveRound3ComputeAndExchangeW3Results,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type1 { .. } => {
                let this = self.inner.clone();

                let w3 = self.inner.compute_w_type3(self.beta, self.gamma);

                Promise::from_future(async move {
                    send_chunks_until_ok!({
                        let mut req =
                            this.connections[this.me + 1].prove_round3_update_w3_product_request();
                        set_chunks!(req, init_w3, &w3);
                        req
                    });
                    Ok(())
                })
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer(format!("Worker {}: prove_round3_compute_and_exchange_t_part3", self.inner.me))]
    fn prove_round3_compute_and_exchange_t_part3(
        &mut self,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart3Params,
        _: plonk_worker::ProveRound3ComputeAndExchangeTPart3Results,
    ) -> Promise<(), capnp::Error> {
        let this = self.inner.clone();
        let alpha = self.alpha;
        let beta = self.beta;
        let gamma = self.gamma;

        Promise::from_future(async move {
            let l = this.n * 2 + 3;
            let (w0w1, w2w3) = join!(
                receive_poly_until_ok!(
                    this.connections[1],
                    prove_round3_get_w3_product_request,
                    get_w3,
                    l
                ),
                receive_poly_until_ok!(
                    this.connections[3],
                    prove_round3_get_w3_product_request,
                    get_w3,
                    l
                ),
            );
            let t = this.compute_t_part3(w0w1, w2w3, alpha, beta, gamma);
            this.share_t(&t[this.n..]).await;
            Ok(())
        })
    }

    #[fn_timer(format!("Worker {}: prove_round3_commit", self.inner.me))]
    fn prove_round3_commit(
        &mut self,
        _: plonk_worker::ProveRound3CommitParams,
        mut results: plonk_worker::ProveRound3CommitResults,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type2 { .. } => {
                self.w3_tmp = Default::default();
            }
            _ => {}
        }
        set_data!(results, set_c, &[self.inner.commit_polynomial(&self.t.lock().unwrap())]);

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round4_evaluate_w", self.inner.me))]
    fn prove_round4_evaluate_w(
        &mut self,
        params: plonk_worker::ProveRound4EvaluateWParams,
        mut results: plonk_worker::ProveRound4EvaluateWResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();
        self.zeta = deserialize(p.get_zeta().unwrap())[0];

        let mut w_of_zeta = self.w_of_zeta.lock().unwrap();
        *w_of_zeta = self.inner.evaluate_w(&self.zeta);

        set_data!(results, set_w, &[*w_of_zeta]);

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round4_evaluate_sigma_or_z", self.inner.me))]
    fn prove_round4_evaluate_sigma_or_z(
        &mut self,
        _: plonk_worker::ProveRound4EvaluateSigmaOrZParams,
        mut results: plonk_worker::ProveRound4EvaluateSigmaOrZResults,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type3 { .. } => {
                set_data!(results, set_sigma_or_z, &[self.inner.evaluate_z(&self.zeta)]);
            }
            _ => {
                set_data!(results, set_sigma_or_z, &[self.inner.evaluate_sigma(&self.zeta)]);
            }
        }

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round5_prepare", self.inner.me))]
    fn prove_round5_prepare(
        &mut self,
        params: plonk_worker::ProveRound5PrepareParams,
        _: plonk_worker::ProveRound5PrepareResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();
        let w_of_zeta = self.w_of_zeta.lock().unwrap().clone();

        let v = deserialize(p.get_v().unwrap())[0];

        self.inner.finalize_t_part1(
            &mut self.t.lock().unwrap(),
            self.zeta,
            w_of_zeta,
            v,
            self.alpha * deserialize::<Fr>(p.get_s1().unwrap())[0],
            deserialize(p.get_s2().unwrap())[0],
        );

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round5_exchange", self.inner.me))]
    fn prove_round5_exchange(
        &mut self,
        _: plonk_worker::ProveRound5ExchangeParams,
        _: plonk_worker::ProveRound5ExchangeResults,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type1 { .. } => {
                let this = self.inner.clone();
                let w_of_zeta = *self.w_of_zeta.lock().unwrap();
                let t = self.t.clone();
                Promise::from_future(async move {
                    let mut t = t.lock().unwrap();
                    send_chunks_until_ok!({
                        let mut req = this.connections[this.me + 1].prove_round5_update_request();
                        req.get().set_w(serialize(&[w_of_zeta]));
                        set_chunks!(req, init_t, &t);
                        req
                    });
                    *t = Default::default();
                    Ok(())
                })
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer(format!("Worker {}: prove_round5_commit", self.inner.me))]
    fn prove_round5_commit(
        &mut self,
        _: plonk_worker::ProveRound5CommitParams,
        mut results: plonk_worker::ProveRound5CommitResults,
    ) -> Promise<(), capnp::Error> {
        let mut t = self.t.lock().unwrap();

        self.inner.finalize_t_part3(&mut t, *self.w_of_zeta.lock().unwrap());

        set_data!(results, set_c_t, &[self.inner.compute_opening_proof(&mut t, &self.zeta)]);
        set_data!(results, set_c_z, &[self.inner.compute_shifted_opening_proof(&self.zeta)]);

        *t = Default::default();

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round2_update_z", self.inner.me))]
    fn prove_round2_update_z(
        &mut self,
        params: plonk_worker::ProveRound2UpdateZParams,
        _: plonk_worker::ProveRound2UpdateZResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let this = self.inner.clone();

        let mut z = vec![];
        get_req_chunks!(p, get_z, |s| z.extend_from_slice(s));
        self.inner.update_z_evals(&mut self.z_tmp.lock().unwrap(), &z);

        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let z = self.z_tmp.clone();
                Promise::from_future(async move {
                    let z = z.lock().unwrap();
                    send_chunks_until_ok!({
                        let mut req = this.connections[4].prove_round2_update_z_request();
                        set_chunks!(req, init_z, &z);
                        req
                    });
                    Ok(())
                })
            }
            Selectors::Type3 { .. } => Promise::ok(()),
            _ => unreachable!(),
        }
    }

    #[fn_timer(format!("Worker {}: prove_round3_update_w1_product", self.inner.me))]
    fn prove_round3_update_w1_product(
        &mut self,
        params: plonk_worker::ProveRound3UpdateW1ProductParams,
        _: plonk_worker::ProveRound3UpdateW1ProductResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let mut w1 = vec![];
                get_req_chunks!(p, get_w1, |s| w1.extend_from_slice(s));

                let ww1 = self.inner.compute_ww_type1(&w1);
                let ww2 = self.inner.compute_ww_type2(&ww1, &mut w1, self.beta, self.gamma);

                self.w1_tmp = ww1;
                self.w2_tmp = ww2;
            }
            _ => unreachable!(),
        }
        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_get_w1_product", self.inner.me))]
    fn prove_round3_get_w1_product(
        &mut self,
        params: plonk_worker::ProveRound3GetW1ProductParams,
        mut results: plonk_worker::ProveRound3GetW1ProductResults,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let start = params.get().unwrap().get_start() as usize;
                let end = params.get().unwrap().get_end() as usize;

                set_chunk!(results, init_w1, &self.w1_tmp[start..end]);
            }
            _ => unreachable!(),
        }

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_get_w2_product", self.inner.me))]
    fn prove_round3_get_w2_product(
        &mut self,
        params: plonk_worker::ProveRound3GetW2ProductParams,
        mut results: plonk_worker::ProveRound3GetW2ProductResults,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let start = params.get().unwrap().get_start() as usize;
                let end = params.get().unwrap().get_end() as usize;

                set_chunk!(results, init_w2, &self.w2_tmp[start..end]);
            }
            _ => unreachable!(),
        }

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_update_w3_product", self.inner.me))]
    fn prove_round3_update_w3_product(
        &mut self,
        params: plonk_worker::ProveRound3UpdateW3ProductParams,
        _: plonk_worker::ProveRound3UpdateW3ProductResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let mut w3 = vec![];
                get_req_chunks!(p, get_w3, |s| w3.extend_from_slice(s));

                self.w3_tmp = self.inner.compute_ww_type3(w3, self.beta, self.gamma);
            }
            _ => unreachable!(),
        }
        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_get_w3_product", self.inner.me))]
    fn prove_round3_get_w3_product(
        &mut self,
        params: plonk_worker::ProveRound3GetW3ProductParams,
        mut results: plonk_worker::ProveRound3GetW3ProductResults,
    ) -> Promise<(), capnp::Error> {
        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let start = params.get().unwrap().get_start() as usize;
                let end = params.get().unwrap().get_end() as usize;

                set_chunk!(results, init_w3, &self.w3_tmp[start..end]);
            }
            _ => unreachable!(),
        }

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round3_update_t", self.inner.me))]
    fn prove_round3_update_t(
        &mut self,
        params: plonk_worker::ProveRound3UpdateTParams,
        _: plonk_worker::ProveRound3UpdateTResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();

        let offset = p.get_offset() as usize;
        let t = p.get_t().unwrap();
        let t_buffer = t.get_data().unwrap();
        if xxhash_rust::xxh3::xxh3_64(t_buffer) != t.get_hash() {
            return Promise::err(capnp::Error::failed("hash mismatch".into()));
        }

        self.inner.update_t(
            &mut self.t.lock().unwrap(),
            crate::utils::deserialize(t_buffer),
            offset,
        );

        Promise::ok(())
    }

    #[fn_timer(format!("Worker {}: prove_round5_update", self.inner.me))]
    fn prove_round5_update(
        &mut self,
        params: plonk_worker::ProveRound5UpdateParams,
        _: plonk_worker::ProveRound5UpdateResults,
    ) -> Promise<(), capnp::Error> {
        let p = params.get().unwrap();
        let w: Fr = deserialize(p.get_w().unwrap())[0];
        let mut t = vec![];
        get_req_chunks!(p, get_t, |s| t.extend_from_slice(s));
        *self.w_of_zeta.lock().unwrap() *= w;
        self.t.lock().unwrap().add_mut(&t);

        match &self.inner.q {
            Selectors::Type2 { .. } => {
                let w_of_zeta = *self.w_of_zeta.lock().unwrap();
                self.inner.finalize_t_part2(&mut self.t.lock().unwrap(), w_of_zeta);

                let this = self.inner.clone();
                let t = self.t.clone();
                Promise::from_future(async move {
                    let mut t = t.lock().unwrap();

                    send_chunks_until_ok!({
                        let mut req = this.connections[4].prove_round5_update_request();
                        req.get().set_w(serialize(&[w_of_zeta]));
                        set_chunks!(req, init_t, &t);
                        req
                    });
                    *t = Default::default();

                    Ok(())
                })
            }
            Selectors::Type3 { .. } => Promise::ok(()),
            _ => unreachable!(),
        }
    }
}

struct Utils;

impl Utils {
    #[fn_timer]
    #[inline]
    fn ifft(domain: &Domain, evals: &mut Vec<Fr>) {
        domain.derange(evals);
        domain.ifft_oi(evals);
        // let domain = Radix2EvaluationDomain::<Fr>::new(elems.len()).unwrap();
        // domain.ifft_in_place(evals);
        // remove_leading_zeros(evals);
    }
}

pub async fn run_worker(me: usize) -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = format!("./data/worker{me}");

    create_dir_all(&bin_path)?;

    let local = tokio::task::LocalSet::new();

    local.spawn_local(async move {
        let listener = tokio::net::TcpListener::bind(WORKERS[me]).await.unwrap();

        let inner = PlonkImplInner::new(me);

        let worker = capnp_rpc::new_client::<plonk_worker::Client, _>(PlonkImpl {
            inner: Arc::new(inner),

            rng: ChaCha20Rng::from_seed([0u8; 32]),

            alpha: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            zeta: Default::default(),

            t: Default::default(),
            t_part1_tmp: Default::default(),

            z_tmp: Default::default(),

            w1_tmp: Default::default(),
            w2_tmp: Default::default(),
            w3_tmp: Default::default(),

            w_of_zeta: Default::default(),
        });

        loop {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let (reader, writer) =
                tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();

            tokio::task::spawn_local(RpcSystem::new(
                Box::new(twoparty::VatNetwork::new(
                    reader,
                    writer,
                    rpc_twoparty_capnp::Side::Server,
                    ReaderOptions { traversal_limit_in_words: Some(usize::MAX), nesting_limit: 64 },
                )),
                Some(worker.clone().client),
            ));
        }
    });

    local.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::thread;

    use tracing::{metadata::LevelFilter, Level, Subscriber};
    use tracing_subscriber::{fmt, prelude::*};

    use super::*;

    fn create_subscriber() -> impl Subscriber + Send + Sync {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(LevelFilter::from_level(Level::TRACE))
    }

    #[test]
    fn test01() -> Result<(), Box<dyn std::error::Error>> {
        let handle = thread::spawn(|| {
            tracing::subscriber::with_default(create_subscriber(), || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        run_worker(0).await.unwrap();
                    });
            });
        });
        tracing::subscriber::with_default(create_subscriber(), || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
                async {
                    run_worker(1).await.unwrap();
                },
            );
        });

        handle.join().unwrap();

        Ok(())
    }

    #[test]
    fn test23() -> Result<(), Box<dyn std::error::Error>> {
        let handle = thread::spawn(|| {
            tracing::subscriber::with_default(create_subscriber(), || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        run_worker(2).await.unwrap();
                    });
            });
        });
        tracing::subscriber::with_default(create_subscriber(), || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
                async {
                    run_worker(3).await.unwrap();
                },
            );
        });

        handle.join().unwrap();

        Ok(())
    }
}
