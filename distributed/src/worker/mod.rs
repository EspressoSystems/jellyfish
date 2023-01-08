use std::{
    cmp::min,
    fs::create_dir_all,
    mem::{size_of, transmute},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use futures::future::join_all;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use stubborn_io::StubbornTcpStream;
use tokio::{
    io,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::TcpListener,
    sync::Mutex,
};

use crate::{
    circuit::PlonkCircuit,
    config::{CHUNK_SIZE, DATA_DIR, IP_NAME_MAP, NUM_WIRE_TYPES, WORKERS},
    gpu::Domain,
    polynomial::VecPolynomial,
    storage::SliceStorage,
    timer,
    utils::CastSlice,
};

mod keygen;
mod round1;
mod round2;
mod round3;
mod round4;
mod round5;
mod utils;

enum Selectors {
    Type1 { a: SliceStorage, h: SliceStorage },
    Type2 { a: SliceStorage, h: SliceStorage, m: SliceStorage },
    Type3 { o: SliceStorage, c: SliceStorage, e: SliceStorage },
}

pub struct PlonkImplInner {
    me: usize,
    data_path: PathBuf,

    n: usize,

    domain1: Domain,
    domain4: Domain,
    domain8: Domain,

    k: Vec<Fr>,
    q: Selectors,
    sigma: SliceStorage,
    sigma_evals: SliceStorage,
    w: SliceStorage,
    w_evals: SliceStorage,
    x: SliceStorage,
    ck: SliceStorage,
    domain1_elements: SliceStorage,

    z: Mutex<Vec<Fr>>,

    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    zeta: Fr,

    t: Mutex<Vec<Fr>>,

    t_part1_tmp: Vec<Fr>,

    w1_tmp: Vec<Fr>,
    w2_tmp: Vec<Fr>,
    w3_tmp: Vec<Fr>,

    w_of_zeta: Mutex<Fr>,
}

#[repr(u8)]
#[derive(Clone, Copy, strum::Display)]
pub enum Method {
    KeyGenPrepare = 0x00,
    KeyGenSetCk = 0x01,
    KeyGenCommit = 0x02,

    ProveInit = 0x0F,

    ProveRound1 = 0x10,

    ProveRound2Compute = 0x20,
    ProveRound2Exchange = 0x21,
    ProveRound2Commit = 0x22,

    ProveRound3Prepare = 0x30,
    ProveRound3ComputeTPart1Type1 = 0x31,
    ProveRound3ExchangeTPart1Type1 = 0x32,
    ProveRound3ExchangeW1 = 0x33,
    ProveRound3ComputeAndExchangeTPart1Type3 = 0x34,
    ProveRound3ComputeAndExchangeTPart2 = 0x35,
    ProveRound3ComputeAndExchangeTPart1Type2 = 0x36,
    ProveRound3Commit = 0x37,

    ProveRound4EvaluateW = 0x40,
    ProveRound4EvaluateSigmaOrZ = 0x41,

    ProveRound5Prepare = 0x50,
    ProveRound5Exchange = 0x51,
    ProveRound5Commit = 0x52,

    ProveRound2UpdateZ = 0x80,

    ProveRound3UpdateW1Product = 0x90,
    ProveRound3UpdateT = 0x92,
    ProveRound3GetW1Product = 0x93,
    ProveRound3GetW2Product = 0x94,
    ProveRound3ComputeW3 = 0x95,
    ProveRound3GetW3 = 0x96,
    ProveRound3GetZ = 0x97,

    ProveRound5Update = 0xA0,
}

#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    HashMismatch = 0x01,
}

pub struct Worker {
    inner: Arc<PlonkImplInner>,
}

impl PlonkImplInner {
    fn new(me: usize) -> Self {
        let data_path = DATA_DIR.join(format!("worker{}", me));

        create_dir_all(&data_path).unwrap();

        Self {
            me,
            ck: SliceStorage::new(data_path.join("srs.ck.bin")),
            x: SliceStorage::new(data_path.join("circuit.inputs.bin")),
            w: SliceStorage::new(data_path.join("circuit.wire.bin")),
            w_evals: SliceStorage::new(data_path.join("circuit.wire_evals.bin")),
            sigma: SliceStorage::new(data_path.join("pk.sigma.bin")),
            sigma_evals: SliceStorage::new(data_path.join("pk.sigma_evals.bin")),
            domain1_elements: SliceStorage::new(data_path.join("pk.domain_elements.bin")),
            q: match me {
                0 | 2 => Selectors::Type1 {
                    a: SliceStorage::new(data_path.join("pk.q_a.bin")),
                    h: SliceStorage::new(data_path.join("pk.q_h.bin")),
                },
                1 | 3 => Selectors::Type2 {
                    a: SliceStorage::new(data_path.join("pk.q_a.bin")),
                    h: SliceStorage::new(data_path.join("pk.q_h.bin")),
                    m: SliceStorage::new(data_path.join("pk.q_m.bin")),
                },
                4 => Selectors::Type3 {
                    o: SliceStorage::new(data_path.join("pk.q_o.bin")),
                    c: SliceStorage::new(data_path.join("pk.q_c.bin")),
                    e: SliceStorage::new(data_path.join("pk.q_e.bin")),
                },
                _ => unreachable!(),
            },
            data_path,

            n: 0,

            domain1: Default::default(),
            domain4: Default::default(),
            domain8: Default::default(),

            k: Default::default(),
            z: Default::default(),

            alpha: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            zeta: Default::default(),

            t: Default::default(),
            t_part1_tmp: Default::default(),

            w1_tmp: Default::default(),
            w2_tmp: Default::default(),
            w3_tmp: Default::default(),

            w_of_zeta: Default::default(),
        }
    }
}

impl PlonkImplInner {
    async fn handle<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        method: Method,
        req: BufReader<R>,
        res: BufWriter<W>,
    ) -> io::Result<()> {
        match method {
            Method::KeyGenPrepare => self.keygen_prepare(req, res).await,
            Method::KeyGenSetCk => self.keygen_set_ck(req, res).await,
            Method::KeyGenCommit => self.keygen_commit(req, res).await,

            Method::ProveInit => self.prove_init(req, res).await,

            Method::ProveRound1 => self.prove_round1(req, res).await,

            Method::ProveRound2Compute => self.prove_round2_compute(req, res).await,
            Method::ProveRound2Exchange => self.prove_round2_exchange(req, res).await,
            Method::ProveRound2Commit => self.prove_round2_commit(req, res).await,

            Method::ProveRound3Prepare => self.prove_round3_prepare(req, res).await,
            Method::ProveRound3ComputeTPart1Type1 => {
                self.prove_round3_compute_t_part1_type1(req, res).await
            }
            Method::ProveRound3ExchangeTPart1Type1 => {
                self.prove_round3_exchange_t_part1_type1(req, res).await
            }
            Method::ProveRound3ExchangeW1 => self.prove_round3_exchange_w1(req, res).await,
            Method::ProveRound3ComputeAndExchangeTPart1Type3 => {
                self.prove_round3_compute_and_exchange_t_part1_type3(req, res).await
            }
            Method::ProveRound3ComputeAndExchangeTPart2 => {
                self.prove_round3_compute_and_exchange_t_part2(req, res).await
            }
            Method::ProveRound3ComputeAndExchangeTPart1Type2 => {
                self.prove_round3_compute_and_exchange_t_part1_type2(req, res).await
            }
            Method::ProveRound3Commit => self.prove_round3_commit(req, res).await,

            Method::ProveRound4EvaluateW => self.prove_round4_evaluate_w(req, res).await,
            Method::ProveRound4EvaluateSigmaOrZ => {
                self.prove_round4_evaluate_sigma_or_z(req, res).await
            }

            Method::ProveRound5Prepare => self.prove_round5_prepare(req, res).await,
            Method::ProveRound5Exchange => self.prove_round5_exchange(req, res).await,
            Method::ProveRound5Commit => self.prove_round5_commit(req, res).await,

            Method::ProveRound2UpdateZ => self.prove_round2_update_z(req, res).await,

            Method::ProveRound3UpdateW1Product => {
                self.prove_round3_update_w1_product(req, res).await
            }
            Method::ProveRound3UpdateT => self.prove_round3_update_t(req, res).await,
            Method::ProveRound3GetW1Product => self.prove_round3_get_w1_product(req, res).await,
            Method::ProveRound3GetW2Product => self.prove_round3_get_w2_product(req, res).await,
            Method::ProveRound3ComputeW3 => self.prove_round3_compute_w3(req, res).await,
            Method::ProveRound3GetW3 => self.prove_round3_get_w3(req, res).await,
            Method::ProveRound3GetZ => self.prove_round3_get_z(req, res).await,

            Method::ProveRound5Update => self.prove_round5_update(req, res).await,
        }
    }

    async fn keygen_prepare<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        self.ck.create()?;
        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn keygen_set_ck<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let hash = req.read_u64_le().await?;
        let length = req.read_u64_le().await?;
        let mut ck_buf = vec![0u8; length as usize];
        req.read_exact(&mut ck_buf).await?;

        if xxhash_rust::xxh3::xxh3_64(&ck_buf) != hash {
            res.write_u8(Status::HashMismatch as u8).await?;
        } else {
            self.ck.append(&ck_buf)?;
            res.write_u8(Status::Ok as u8).await?;
        }
        res.flush().await?;

        Ok(())
    }

    async fn keygen_commit<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut seed = [0u8; 32];
        req.read_exact(&mut seed).await?;

        let PlonkCircuit {
            num_vars,
            gates,
            wire_variables,
            pub_input_gate_ids,
            witness,
            eval_domain,
            ..
        } = self.init_circuit(seed);
        let domain_elements = eval_domain.elements().collect::<Vec<_>>();
        self.init_domains(&domain_elements);
        self.init_k(NUM_WIRE_TYPES);
        if self.me == 4 {
            self.store_public_inputs(
                pub_input_gate_ids
                    .into_par_iter()
                    .map(|gate_id| witness[wire_variables[NUM_WIRE_TYPES - 1][gate_id]])
                    .collect(),
            );
        }
        self.store_w_evals(&wire_variables[self.me], witness);

        res.write_u8(Status::Ok as u8).await?;
        res.write_all(
            [self.init_and_commit_sigma(wire_variables, num_vars, domain_elements)].cast(),
        )
        .await?;
        res.write_all(self.init_and_commit_selectors(gates).cast()).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_init<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        if self.n == 0 {
            self.init_domains(&self.domain1_elements.mmap()?);
            self.init_k(NUM_WIRE_TYPES);
        }

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round1<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        res.write_u8(Status::Ok as u8).await?;
        res.write_all([self.init_and_commit_w()].cast()).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round2_compute<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut data = [0; size_of::<Fr>() * 2];
        req.read_exact(&mut data).await?;
        let data = data.cast::<Fr>();
        unsafe {
            let this = &mut *(self as *const _ as *mut Self);
            this.beta = data[0];
            this.gamma = data[1];
        }

        *self.z.lock().await = self.compute_z_evals(data[0], data[1]);

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round2_exchange<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let z_tmp = self.z.lock().await;
        let z_tmp_buf = z_tmp.cast();

        let mut peer = Self::peer(self.me + 1).await;
        loop {
            peer.write_u8(Method::ProveRound2UpdateZ as u8).await?;
            peer.write_u64_le(xxhash_rust::xxh3::xxh3_64(z_tmp_buf)).await?;
            peer.write_u64_le(z_tmp_buf.len() as u64).await?;
            peer.write_all(z_tmp_buf).await?;
            peer.flush().await?;

            match unsafe { transmute(peer.read_u8().await?) } {
                Status::Ok => break,
                Status::HashMismatch => continue,
            }
        }

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round2_commit<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        res.write_u8(Status::Ok as u8).await?;
        res.write_all([self.compute_and_commit_z(&mut self.z.lock().await as &mut Vec<_>)].cast())
            .await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_prepare<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut alpha = [0; size_of::<Fr>()];
        req.read_exact(&mut alpha).await?;
        let alpha = alpha.cast::<Fr>()[0];
        unsafe {
            let this = &mut *(self as *const _ as *mut Self);
            this.alpha = alpha;
        }

        match &self.q {
            Selectors::Type3 { .. } => {
                *self.t.lock().await = self.compute_t_part4(alpha, &self.z.lock().await);
            }
            _ => {
                *self.z.lock().await = Default::default();
            }
        }

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_compute_t_part1_type1<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type1 { .. } | Selectors::Type2 { .. } => unsafe {
                let this = &mut *(self as *const _ as *mut Self);
                this.t_part1_tmp = self.compute_t_part1_type1();
            },
            Selectors::Type3 { .. } => {
                self.update_t(
                    &mut self.t.lock().await as &mut Vec<_>,
                    &self.compute_t_part1_type1()[self.n..],
                    0,
                );
            }
        }

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_exchange_t_part1_type1<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type1 { .. } | Selectors::Type2 { .. } => {
                Self::share_t(&mut Self::peers().await, &self.t_part1_tmp[self.n..], self.n + 2)
                    .await?;

                unsafe {
                    let this = &mut *(self as *const _ as *mut Self);
                    this.t_part1_tmp = Default::default();
                }
            }
            _ => unreachable!(),
        }

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_exchange_w1<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type1 { .. } => {
                let w = self.w.mmap::<u8>().unwrap();

                let mut peer = Self::peer(self.me + 1).await;
                loop {
                    peer.write_u8(Method::ProveRound3UpdateW1Product as u8).await?;
                    peer.write_u64_le(xxhash_rust::xxh3::xxh3_64(&w)).await?;
                    peer.write_u64_le(w.len() as u64).await?;
                    peer.write_all(&w).await?;
                    peer.flush().await?;

                    match unsafe { transmute(peer.read_u8().await?) } {
                        Status::Ok => break,
                        Status::HashMismatch => continue,
                    }
                }
            }
            _ => unreachable!(),
        }

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_compute_and_exchange_t_part1_type3<
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    >(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let l = self.n * 2 + 3;

        let mut peers = Self::peers().await;

        let w0w1 =
            Self::receive_poly_until_ok(&mut peers[1], Method::ProveRound3GetW1Product, l).await?;
        let w2w3 =
            Self::receive_poly_until_ok(&mut peers[3], Method::ProveRound3GetW1Product, l).await?;

        let t = self.compute_t_part1_type3(w0w1, w2w3);
        Self::share_t(&mut peers, &t[self.n..], self.n + 2).await?;

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_compute_and_exchange_t_part2<
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    >(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let l = self.n * 2 + 3;

        let mut peers = Self::peers().await;

        let w0w1 =
            Self::receive_poly_until_ok(&mut peers[1], Method::ProveRound3GetW2Product, l).await?;
        let w2w3 =
            Self::receive_poly_until_ok(&mut peers[3], Method::ProveRound3GetW2Product, l).await?;

        let t = self.compute_t_part2(w0w1, w2w3, &self.z.lock().await);
        Self::share_t(&mut peers, &t[self.n..], self.n + 2).await?;

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_compute_and_exchange_t_part1_type2<
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    >(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let ww = unsafe {
            let this = &mut *(self as *const _ as *mut Self);
            this.w2_tmp = Default::default();
            this.w1_tmp.split_off(0)
        };

        let t = self.compute_t_part1_type2(ww);
        Self::share_t(&mut Self::peers().await, &t[self.n..], self.n + 2).await?;

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_commit<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        unsafe {
            let this = &mut *(self as *const _ as *mut Self);
            this.w3_tmp = Default::default();
        }

        res.write_u8(Status::Ok as u8).await?;
        res.write_all([self.commit_polynomial(&self.t.lock().await)].cast()).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round4_evaluate_w<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut zeta = [0; size_of::<Fr>()];
        req.read_exact(&mut zeta).await?;
        let zeta = zeta.cast::<Fr>()[0];
        unsafe {
            let this = &mut *(self as *const _ as *mut Self);
            this.zeta = zeta;
        }

        let mut w_of_zeta = self.w_of_zeta.lock().await;
        *w_of_zeta = self.evaluate_w();

        res.write_u8(Status::Ok as u8).await?;
        res.write_all([*w_of_zeta].cast()).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round4_evaluate_sigma_or_z<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        res.write_u8(Status::Ok as u8).await?;
        match &self.q {
            Selectors::Type3 { .. } => {
                res.write_all([self.evaluate_z(&self.z.lock().await)].cast()).await?;
            }
            _ => {
                res.write_all([self.evaluate_sigma()].cast()).await?;
            }
        }
        res.flush().await?;

        Ok(())
    }

    async fn prove_round5_prepare<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut data = [0; size_of::<Fr>() * 3];
        req.read_exact(&mut data).await?;
        let data = data.cast::<Fr>();
        let v = data[0];
        let s1 = data[1];
        let s2 = data[2];

        self.finalize_t_part1(
            &mut self.t.lock().await as &mut Vec<Fr>,
            &self.z.lock().await,
            *self.w_of_zeta.lock().await,
            v,
            s1,
            s2,
        );
        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round5_exchange<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type1 { .. } => {
                let w_of_zeta = *self.w_of_zeta.lock().await;
                let mut t = self.t.lock().await;
                let t_buf = t.cast();

                let mut peer = Self::peer(self.me + 1).await;
                loop {
                    peer.write_u8(Method::ProveRound5Update as u8).await?;
                    peer.write_all([w_of_zeta].cast()).await?;
                    peer.write_u64_le(xxhash_rust::xxh3::xxh3_64(t_buf)).await?;
                    peer.write_u64_le(t_buf.len() as u64).await?;
                    peer.write_all(t_buf).await?;
                    peer.flush().await?;

                    match unsafe { transmute(peer.read_u8().await?) } {
                        Status::Ok => break,
                        Status::HashMismatch => continue,
                    }
                }
                *t = Default::default();
            }
            _ => unreachable!(),
        }
        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round5_commit<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut t = self.t.lock().await;

        self.finalize_t_part3(&mut t, *self.w_of_zeta.lock().await);

        res.write_u8(Status::Ok as u8).await?;
        res.write_all(
            [
                self.compute_opening_proof(&mut t),
                self.compute_shifted_opening_proof(&mut self.z.lock().await as &mut Vec<_>),
            ]
            .cast(),
        )
        .await?;
        res.flush().await?;

        *t = Default::default();

        Ok(())
    }

    async fn prove_round2_update_z<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let hash = req.read_u64_le().await?;
        let length = req.read_u64_le().await?;
        let mut z_buf = vec![0u8; length as usize];
        req.read_exact(&mut z_buf).await?;

        if xxhash_rust::xxh3::xxh3_64(&z_buf) != hash {
            res.write_u8(Status::HashMismatch as u8).await?;
        } else {
            let z = z_buf.cast::<Fr>();
            let mut z_tmp = self.z.lock().await;
            self.update_z_evals(&mut z_tmp, z);
            let z_tmp_buf = z_tmp.cast();
            match &self.q {
                Selectors::Type2 { .. } => {
                    let mut peer = Self::peer(4).await;
                    loop {
                        peer.write_u8(Method::ProveRound2UpdateZ as u8).await?;
                        peer.write_u64_le(xxhash_rust::xxh3::xxh3_64(z_tmp_buf)).await?;
                        peer.write_u64_le(z_tmp_buf.len() as u64).await?;
                        peer.write_all(z_tmp_buf).await?;
                        peer.flush().await?;

                        match unsafe { transmute(peer.read_u8().await?) } {
                            Status::Ok => break,
                            Status::HashMismatch => continue,
                        }
                    }
                }
                Selectors::Type3 { .. } => {}
                _ => unreachable!(),
            }
            res.write_u8(Status::Ok as u8).await?;
        }
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_update_w1_product<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type2 { .. } => {
                let hash = req.read_u64_le().await?;
                let length = req.read_u64_le().await?;
                let mut w1 = vec![Fr::zero(); length as usize / size_of::<Fr>()];
                let w1_buf = w1.cast_mut();
                req.read_exact(w1_buf).await?;
                if xxhash_rust::xxh3::xxh3_64(w1_buf) != hash {
                    res.write_u8(Status::HashMismatch as u8).await?;
                } else {
                    self.compute_ww_type1_and_type2(w1);

                    res.write_u8(Status::Ok as u8).await?;
                }
                res.flush().await?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    async fn prove_round3_get_w1_product<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type2 { .. } => {
                let start = req.read_u64_le().await? as usize;
                let end = req.read_u64_le().await? as usize;

                Self::send_poly_chunk(res, &self.w1_tmp, start, end).await?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    async fn prove_round3_get_w2_product<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type2 { .. } => {
                let start = req.read_u64_le().await? as usize;
                let end = req.read_u64_le().await? as usize;

                Self::send_poly_chunk(res, &self.w2_tmp, start, end).await?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    async fn prove_round3_update_t<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let offset = req.read_u64_le().await? as usize;
        let hash = req.read_u64_le().await?;
        let length = req.read_u64_le().await?;
        let mut t_buf = vec![0u8; length as usize];
        req.read_exact(&mut t_buf).await?;
        if xxhash_rust::xxh3::xxh3_64(&t_buf) != hash {
            res.write_u8(Status::HashMismatch as u8).await?;
        } else {
            let t = t_buf.cast::<Fr>();
            self.update_t(&mut self.t.lock().await as &mut Vec<_>, t, offset);

            res.write_u8(Status::Ok as u8).await?;
        }
        res.flush().await?;
        Ok(())
    }

    async fn prove_round3_compute_w3<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        self.compute_w_type3();

        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn prove_round3_get_w3<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        res: BufWriter<W>,
    ) -> io::Result<()> {
        let start = req.read_u64_le().await? as usize;
        let end = req.read_u64_le().await? as usize;

        Self::send_poly_chunk(res, &self.w3_tmp, start, end).await?;
        Ok(())
    }

    async fn prove_round3_get_z<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        res: BufWriter<W>,
    ) -> io::Result<()> {
        match &self.q {
            Selectors::Type3 { .. } => {
                let start = req.read_u64_le().await? as usize;
                let end = req.read_u64_le().await? as usize;

                Self::send_poly_chunk(res, &self.z.lock().await, start, end).await?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    async fn prove_round5_update<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut w = [0; size_of::<Fr>()];
        req.read_exact(&mut w).await?;
        let w = w.cast::<Fr>()[0];

        let hash = req.read_u64_le().await?;
        let length = req.read_u64_le().await?;
        let mut t_buf = vec![0u8; length as usize];
        req.read_exact(&mut t_buf).await?;

        if xxhash_rust::xxh3::xxh3_64(&t_buf) != hash {
            res.write_u8(Status::HashMismatch as u8).await?;
        } else {
            let t = t_buf.cast::<Fr>();

            let mut w_of_zeta = self.w_of_zeta.lock().await;
            *w_of_zeta *= w;
            self.t.lock().await.add_mut(t);

            match &self.q {
                Selectors::Type2 { .. } => {
                    self.finalize_t_part2(&mut self.t.lock().await as &mut Vec<_>, *w_of_zeta);

                    let mut t = self.t.lock().await;
                    let t_buf = t.cast();
                    let mut peer = Self::peer(4).await;
                    loop {
                        peer.write_u8(Method::ProveRound5Update as u8).await?;
                        peer.write_all([*w_of_zeta].cast()).await?;
                        peer.write_u64_le(xxhash_rust::xxh3::xxh3_64(t_buf)).await?;
                        peer.write_u64_le(t_buf.len() as u64).await?;
                        peer.write_all(t_buf).await?;
                        peer.flush().await?;

                        match unsafe { transmute(peer.read_u8().await?) } {
                            Status::Ok => break,
                            Status::HashMismatch => continue,
                        }
                    }
                    *t = Default::default();
                }
                Selectors::Type3 { .. } => {}
                _ => unreachable!(),
            }

            res.write_u8(Status::Ok as u8).await?;
        }
        res.flush().await?;

        Ok(())
    }
}

impl PlonkImplInner {
    pub async fn share_t(
        connections: &mut [StubbornTcpStream<&'static SocketAddr>],
        t: &[Fr],
        t_size_per_peer: usize,
    ) -> io::Result<()> {
        let chunk_size = CHUNK_SIZE / size_of::<Fr>();
        for i in (0..t_size_per_peer).step_by(chunk_size) {
            join_all(t.chunks(t_size_per_peer).zip(connections.iter_mut().rev()).map(
                |(t, peer)| async move {
                    if i < t.len() {
                        let chunk = t[i..min(i + chunk_size, t.len())].cast();
                        let hash = xxhash_rust::xxh3::xxh3_64(chunk);
                        loop {
                            peer.write_u8(Method::ProveRound3UpdateT as u8).await.unwrap();
                            peer.write_u64_le(i as u64).await.unwrap();
                            peer.write_u64_le(hash).await.unwrap();
                            peer.write_u64_le(chunk.len() as u64).await.unwrap();
                            peer.write_all(chunk).await.unwrap();
                            peer.flush().await.unwrap();

                            match unsafe { transmute(peer.read_u8().await.unwrap()) } {
                                Status::Ok => break,
                                Status::HashMismatch => continue,
                            }
                        }
                    }
                },
            ))
            .await;
        }
        Ok(())
    }

    pub async fn send_poly_chunk<W: AsyncWrite + Unpin>(
        mut res: BufWriter<W>,
        poly: &[Fr],
        start: usize,
        end: usize,
    ) -> io::Result<()> {
        let buf = poly[start..end].cast();

        res.write_u8(Status::Ok as u8).await?;
        res.write_u64_le(xxhash_rust::xxh3::xxh3_64(buf)).await?;
        res.write_all(buf).await?;
        res.flush().await?;

        Ok(())
    }

    pub async fn receive_poly_until_ok(
        peer: &mut StubbornTcpStream<&'static SocketAddr>,
        method: Method,
        length: usize,
    ) -> io::Result<Vec<Fr>> {
        let mut w: Vec<Fr> = vec![];
        let mut i = 0;
        let chunk_size = CHUNK_SIZE / size_of::<Fr>();
        while i < length {
            loop {
                peer.write_u8(method as u8).await?;
                peer.write_u64_le(i as u64).await?;
                peer.write_u64_le(min(i + chunk_size, length) as u64).await?;
                peer.flush().await?;

                match unsafe { transmute(peer.read_u8().await?) } {
                    Status::Ok => {}
                    _ => panic!(),
                }

                let hash = peer.read_u64_le().await?;
                let mut w_buffer = vec![0u8; min(chunk_size, length - i) * size_of::<Fr>()];
                peer.read_exact(&mut w_buffer).await?;

                if xxhash_rust::xxh3::xxh3_64(&w_buffer) == hash {
                    w.extend_from_slice(w_buffer.cast());
                    break;
                }
            }
            i += chunk_size;
        }
        Ok(w)
    }
}

impl Worker {
    pub fn new(me: usize) -> Self {
        Self { inner: Arc::new(PlonkImplInner::new(me)) }
    }

    pub async fn start(&self) -> io::Result<()> {
        let my_addr = WORKERS[self.inner.me];
        let my_name = IP_NAME_MAP.get(&my_addr.ip()).unwrap();

        let listener = TcpListener::bind(my_addr).await?;

        println!("{} listening on: {}", my_name, my_addr);

        while let Ok((mut stream, addr)) = listener.accept().await {
            let peer_addr = addr.ip();
            if IP_NAME_MAP.contains_key(&peer_addr) {
                let peer_name = IP_NAME_MAP.get(&peer_addr).unwrap();
                println!("{} ({}) connected", peer_name, peer_addr);
                stream.set_nodelay(true)?;
                let this = self.inner.clone();
                tokio::spawn(async move {
                    loop {
                        let (read, write) = stream.split();

                        let mut req = BufReader::new(read);
                        let res = BufWriter::new(write);
                        match req.read_u8().await {
                            Ok(method) => {
                                let method: Method = unsafe { transmute(method) };
                                timer!(format!("{} -> {}: {}", peer_name, my_name, method), {
                                    this.handle(method, req, res).await?;
                                });
                            }
                            Err(_) => {
                                println!("{} ({}) disconnected", peer_name, peer_addr);
                                break;
                            }
                        }
                    }
                    Ok::<(), io::Error>(())
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test01() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(async {
            Worker::new(0).start().await.unwrap();
        });
        Worker::new(1).start().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test23() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(async {
            Worker::new(2).start().await.unwrap();
        });
        Worker::new(3).start().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test4() -> Result<(), Box<dyn std::error::Error>> {
        Worker::new(4).start().await?;
        Ok(())
    }
}
