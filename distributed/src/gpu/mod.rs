// Copyright Filecoin
//
// This file is adapted from the ec-gpu library, which is licensed under either of the following licenses:
// - Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
// - MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
//
// See https://github.com/filecoin-project/ec-gpu for more information.

use std::{
    cmp::{self, min},
    mem::size_of,
    sync::Mutex,
};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use once_cell::sync::Lazy;
use rayon::{
    prelude::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::{ParallelSlice, ParallelSliceMut},
};
use rust_gpu_tools::{cuda, Device, GPUError, LocalBuffer};

use crate::{
    config::GPU_CONFIG,
    mmap::{Mmap, MutMmap},
};

/// On the GPU, the exponents are split into windows, this is the maximum number of such windows.
const MAX_WINDOW_SIZE: usize = 10;
/// In CUDA this is the number of blocks per grid (grid size).
const LOCAL_WORK_SIZE: usize = 128;
/// Let 20% of GPU memory be free, this is an arbitrary value.
const MEMORY_PADDING: f64 = 0.2f64;
/// The Nvidia Ampere architecture is compute capability major version 8.
const AMPERE: u32 = 8;

const LOG2_MAX_ELEMENTS: usize = 32; // At most 2^32 elements is supported.
const MAX_LOG2_RADIX: u32 = 8; // Radix256
const MAX_LOG2_LOCAL_WORK_SIZE: u32 = 7; // 128

/// Divide and ceil to the next value.
const fn div_ceil(a: usize, b: usize) -> usize {
    if a % b == 0 {
        a / b
    } else {
        (a / b) + 1
    }
}

/// The number of units the work is split into. One unit will result in one CUDA thread.
///
/// Based on empirical results, it turns out that on Nvidia devices with the Ampere architecture,
/// it's faster to use two times the number of work units.
const fn work_units(compute_units: u32, compute_capabilities: Option<(u32, u32)>) -> usize {
    match compute_capabilities {
        Some((AMPERE, _)) => LOCAL_WORK_SIZE * compute_units as usize * 2,
        _ => LOCAL_WORK_SIZE * compute_units as usize,
    }
}

pub struct Kernel {
    program: cuda::Program,
    /// The number of exponentiations the GPU can handle in a single execution of the kernel.
    n: usize,
    /// The number of units the work is split into. It will results in this amount of threads on
    /// the GPU.
    work_units: usize,
}

/// Calculates the maximum number of terms that can be put onto the GPU memory.
fn calc_chunk_size(mem: u64, work_units: usize) -> usize {
    let aff_size = std::mem::size_of::<G1Affine>();
    assert_eq!(aff_size, 104);
    let exp_size = exp_size();
    let proj_size = std::mem::size_of::<G1Projective>();

    // Leave `MEMORY_PADDING` percent of the memory free.
    let max_memory = ((mem as f64) * (1f64 - MEMORY_PADDING)) as usize;
    // The amount of memory (in bytes) of a single term.
    let term_size = aff_size + exp_size;
    // The number of buckets needed for one work unit
    let max_buckets_per_work_unit = 1 << MAX_WINDOW_SIZE;
    // The amount of memory (in bytes) we need for the intermediate steps (buckets).
    let buckets_size = work_units * max_buckets_per_work_unit * proj_size;
    // The amount of memory (in bytes) we need for the results.
    let results_size = work_units * proj_size;

    (max_memory - buckets_size - results_size) / term_size
}

/// The size of the exponent in bytes.
///
/// It's the actual bytes size it needs in memory, not it's theoratical bit size.
fn exp_size() -> usize {
    std::mem::size_of::<<Fr as PrimeField>::BigInt>()
}

impl Kernel {
    /// Create a new Multiexp kernel instance for a device.
    ///
    /// The `maybe_abort` function is called when it is possible to abort the computation, without
    /// leaving the GPU in a weird state. If that function returns `true`, execution is aborted.
    pub fn create(binary: &[u8], device: &Device) -> Self {
        let program = cuda::Program::from_bytes(device.cuda_device().unwrap(), binary).unwrap();
        let mem = device.memory();
        let compute_units = device.compute_units();
        let compute_capability = device.compute_capability();
        let work_units = work_units(compute_units, compute_capability);
        let chunk_size = calc_chunk_size(mem, work_units);

        Kernel { program, n: chunk_size, work_units }
    }

    /// Run the actual multiexp computation on the GPU.
    ///
    /// The number of `bases` and `exponents` are determined by [`SingleMultiexpKernel`]`::n`, this
    /// means that it is guaranteed that this amount of calculations fit on the GPU this kernel is
    /// running on.
    fn multiexp_inner(&self, bases: &[G1Affine], exponents: &[Fr]) -> G1Projective {
        let len = min(bases.len(), exponents.len());

        let window_size = self.calc_window_size(len);
        // windows_size * num_windows needs to be >= 256 in order for the kernel to work correctly.
        let num_windows = div_ceil(256, window_size);
        let num_groups = self.work_units / num_windows;
        let bucket_len = 1 << window_size;

        // Each group will have `num_windows` threads and as there are `num_groups` groups, there will
        // be `num_groups` * `num_windows` threads in total.
        // Each thread will use `num_groups` * `num_windows` * `bucket_len` buckets.

        let results = self
            .program
            .run(
                |program, _arg| -> Result<Vec<G1Projective>, GPUError> {
                    let base_buffer = program.create_buffer_from_slice(bases)?;
                    let exp_buffer = program.create_buffer_from_slice(exponents)?;

                    // It is safe as the GPU will initialize that buffer
                    let bucket_buffer = unsafe {
                        program.create_buffer::<G1Projective>(self.work_units * bucket_len)?
                    };
                    // It is safe as the GPU will initialize that buffer
                    let result_buffer =
                        unsafe { program.create_buffer::<G1Projective>(self.work_units)? };

                    // The global work size follows CUDA's definition and is the number of
                    // `LOCAL_WORK_SIZE` sized thread groups.
                    let global_work_size = div_ceil(num_windows * num_groups, LOCAL_WORK_SIZE);

                    let kernel_name = format!("multiexp");
                    let kernel =
                        program.create_kernel(&kernel_name, global_work_size, LOCAL_WORK_SIZE)?;

                    kernel
                        .arg(&base_buffer)
                        .arg(&bucket_buffer)
                        .arg(&result_buffer)
                        .arg(&exp_buffer)
                        .arg(&(len as u32))
                        .arg(&(num_groups as u32))
                        .arg(&(num_windows as u32))
                        .arg(&(window_size as u32))
                        .run()?;

                    let mut results = vec![G1Projective::zero(); self.work_units];
                    program.read_into_buffer(&result_buffer, &mut results)?;

                    Ok(results)
                },
                (),
            )
            .unwrap();

        // Using the algorithm below, we can calculate the final result by accumulating the results
        // of those `NUM_GROUPS` * `NUM_WINDOWS` threads.
        let mut acc = G1Projective::default();
        let mut bits = 0;
        let exp_bits = exp_size() * 8;
        for i in 0..num_windows {
            let w = std::cmp::min(window_size, exp_bits - bits);
            for _ in 0..w {
                acc = acc.double();
            }
            for g in 0..num_groups {
                acc += &results[g * num_windows + i];
            }
            bits += w; // Process the next window
        }

        acc
    }

    pub fn multiexp(&self, bases: &[G1Affine], exps: &[Fr]) -> G1Projective {
        let n = self.n;
        let mut result = G1Projective::default();
        for (bases, exps) in bases.chunks(n).zip(exps.chunks(n)) {
            result += self.multiexp_inner(bases, exps);
        }

        result
    }

    /// Calculates the window size, based on the given number of terms.
    ///
    /// For best performance, the window size is reduced, so that maximum parallelism is possible.
    /// If you e.g. have put only a subset of the terms into the GPU memory, then a smaller window
    /// size leads to more windows, hence more units to work on, as we split the work into
    /// `num_windows * num_groups`.
    fn calc_window_size(&self, num_terms: usize) -> usize {
        // The window size was determined by running the `gpu_multiexp_consistency` test and
        // looking at the resulting numbers.
        let window_size = ((div_ceil(num_terms, self.work_units) as f64).log2() as usize) + 2;
        std::cmp::min(window_size, MAX_WINDOW_SIZE)
    }

    fn fft_inner(&self, input: &mut [Fr], pq: &[Fr], omegas: &[Fr], log_n: u32) {
        self.program
            .run(
                |program, input| -> Result<(), GPUError> {
                    let n = 1 << log_n;
                    // All usages are safe as the buffers are initialized from either the host or the GPU
                    // before they are read.
                    let mut src_buffer = unsafe { program.create_buffer::<Fr>(n)? };
                    let mut dst_buffer = unsafe { program.create_buffer::<Fr>(n)? };
                    // The precalculated values pq` and `omegas` are valid for radix degrees up to `max_deg`
                    let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);

                    let pq_buffer = program.create_buffer_from_slice(&pq)?;
                    let omegas_buffer = program.create_buffer_from_slice(&omegas)?;

                    program.write_from_buffer(&mut src_buffer, &*input)?;
                    // Specifies log2 of `p`, (http://www.bealto.com/gpu-fft_group-1.html)
                    let mut log_p = 0u32;
                    // Each iteration performs a FFT round
                    while log_p < log_n {
                        // 1=>radix2, 2=>radix4, 3=>radix8, ...
                        let deg = cmp::min(max_deg, log_n - log_p);

                        let local_work_size = 1 << (deg - 1);
                        let global_work_size = n >> deg;
                        let kernel = program.create_kernel(
                            "radix_fft",
                            global_work_size,
                            local_work_size,
                        )?;
                        kernel
                            .arg(&src_buffer)
                            .arg(&dst_buffer)
                            .arg(&pq_buffer)
                            .arg(&omegas_buffer)
                            .arg(&LocalBuffer::<Fr>::new(1 << deg))
                            .arg(&(n as u32))
                            .arg(&log_p)
                            .arg(&deg)
                            .arg(&max_deg)
                            .run()?;

                        log_p += deg;
                        std::mem::swap(&mut src_buffer, &mut dst_buffer);
                    }

                    program.read_into_buffer(&src_buffer, input)?;

                    Ok(())
                },
                input,
            )
            .unwrap()
    }

    fn batch_fft_inner(&self, input: &mut [Fr], pq: &[Fr], omegas: &[Fr], log_n: u32, m: usize) {
        self.program
            .run(
                |program, input| -> Result<(), GPUError> {
                    let n = 1 << log_n;
                    // All usages are safe as the buffers are initialized from either the host or the GPU
                    // before they are read.
                    let mut src_buffer = unsafe { program.create_buffer::<Fr>(n * m)? };
                    let mut dst_buffer = unsafe { program.create_buffer::<Fr>(n * m)? };
                    // The precalculated values pq` and `omegas` are valid for radix degrees up to `max_deg`
                    let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);

                    let pq_buffer = program.create_buffer_from_slice(&pq)?;
                    let omegas_buffer = program.create_buffer_from_slice(&omegas)?;

                    program.write_from_buffer(&mut src_buffer, &*input)?;
                    // Specifies log2 of `p`, (http://www.bealto.com/gpu-fft_group-1.html)
                    let mut log_p = 0u32;
                    // Each iteration performs a FFT round
                    while log_p < log_n {
                        // 1=>radix2, 2=>radix4, 3=>radix8, ...
                        let deg = cmp::min(max_deg, log_n - log_p);

                        let local_work_size = 1 << cmp::min(deg - 1, MAX_LOG2_LOCAL_WORK_SIZE);
                        let global_work_size = n >> deg;
                        let kernel_name = format!("batch_radix_fft");
                        let kernel = program.create_kernel(
                            &kernel_name,
                            global_work_size,
                            local_work_size,
                        )?;
                        kernel
                            .arg(&src_buffer)
                            .arg(&dst_buffer)
                            .arg(&pq_buffer)
                            .arg(&omegas_buffer)
                            .arg(&LocalBuffer::<Fr>::new(1 << deg))
                            .arg(&(m as u32))
                            .arg(&(n as u32))
                            .arg(&log_p)
                            .arg(&deg)
                            .arg(&max_deg)
                            .run()?;

                        log_p += deg;
                        std::mem::swap(&mut src_buffer, &mut dst_buffer);
                    }

                    program.read_into_buffer(&src_buffer, input)?;

                    Ok(())
                },
                input,
            )
            .unwrap()
    }

    pub fn butterfly_io2<F: FftField>(
        &self,
        x: &mut [F],
        y: &mut [F],
        omegas: &[F],
        num_chunks: usize,
        offset: usize,
    ) {
        self.program
            .run(
                |program, (x, y)| -> Result<(), GPUError> {
                    let x_buffer = program.create_buffer_from_slice(x)?;
                    let y_buffer = program.create_buffer_from_slice(y)?;
                    let omegas_buffer = program.create_buffer_from_slice(omegas)?;

                    let kernel = if x.len() > 1024 {
                        program.create_kernel("butterfly_io_update", x.len() / 1024, 1024)?
                    } else {
                        program.create_kernel("butterfly_io_update", 1, x.len())?
                    };
                    kernel
                        .arg(&x_buffer)
                        .arg(&y_buffer)
                        .arg(&omegas_buffer)
                        .arg(&(num_chunks as u32))
                        .arg(&(offset as u32))
                        .run()?;

                    program.read_into_buffer(&x_buffer, x)?;
                    program.read_into_buffer(&y_buffer, y)?;
                    Ok(())
                },
                (x, y),
            )
            .unwrap()
    }

    pub fn butterfly_io3<F: FftField>(&self, input: &mut [F], n: usize, omegas: &[F]) {
        self.program
            .run(
                |program, input| -> Result<(), GPUError> {
                    let mut input_buffer = unsafe { program.create_buffer::<F>(input.len())? };
                    program.write_from_buffer(&mut input_buffer, &*input)?;
                    let omegas_buffer = program.create_buffer_from_slice(omegas)?;

                    let mut gap = input.len() / 2;
                    let t = 512;
                    while gap > 0 {
                        let local_work_size = min(t, gap);
                        let global_work_size = input.len() / (2 * local_work_size);
                        let kernel = program.create_kernel(
                            "butterfly_io_finalize",
                            global_work_size,
                            local_work_size,
                        )?;

                        kernel
                            .arg(&input_buffer)
                            .arg(&(n as u32))
                            .arg(&omegas_buffer)
                            .arg(&(gap as u32))
                            .arg(&LocalBuffer::<Fr>::new(2 * t))
                            .run()?;

                        gap /= 2 * t;
                    }
                    program.read_into_buffer(&input_buffer, input)?;
                    Ok(())
                },
                input,
            )
            .unwrap()
    }

    pub fn butterfly_oi2<F: FftField>(
        &self,
        x: &mut [F],
        y: &mut [F],
        omegas: &[F],
        num_chunks: usize,
        offset: usize,
    ) {
        self.program
            .run(
                |program, (x, y)| -> Result<(), GPUError> {
                    let x_buffer = program.create_buffer_from_slice(x)?;
                    let y_buffer = program.create_buffer_from_slice(y)?;
                    let omegas_buffer = program.create_buffer_from_slice(omegas)?;

                    let kernel = if x.len() > 1024 {
                        program.create_kernel("butterfly_oi_update", x.len() / 1024, 1024)?
                    } else {
                        program.create_kernel("butterfly_oi_update", 1, x.len())?
                    };
                    kernel
                        .arg(&x_buffer)
                        .arg(&y_buffer)
                        .arg(&omegas_buffer)
                        .arg(&(num_chunks as u32))
                        .arg(&(offset as u32))
                        .run()?;

                    program.read_into_buffer(&x_buffer, x)?;
                    program.read_into_buffer(&y_buffer, y)?;
                    Ok(())
                },
                (x, y),
            )
            .unwrap()
    }

    pub fn butterfly_oi3<F: FftField>(&self, input: &mut [F], n: usize, omegas: &[F]) {
        self.program
            .run(
                |program, input| -> Result<(), GPUError> {
                    let mut input_buffer = unsafe { program.create_buffer::<F>(input.len())? };
                    program.write_from_buffer(&mut input_buffer, &*input)?;
                    let omegas_buffer = program.create_buffer_from_slice(omegas)?;

                    let mut gap = 1;
                    let t = 512;
                    while gap < input.len() {
                        let local_work_size = min(t, input.len() / (2 * gap));
                        let global_work_size = input.len() / (2 * local_work_size);
                        let kernel = program.create_kernel(
                            "butterfly_oi_finalize",
                            global_work_size,
                            local_work_size,
                        )?;

                        kernel
                            .arg(&input_buffer)
                            .arg(&(n as u32))
                            .arg(&omegas_buffer)
                            .arg(&(gap as u32))
                            .arg(&LocalBuffer::<Fr>::new(2 * t))
                            .run()?;

                        gap *= 2 * t;
                    }
                    program.read_into_buffer(&input_buffer, input)?;
                    Ok(())
                },
                input,
            )
            .unwrap()
    }

    pub fn fft(&self, input: &mut [Fr], group_gen: &Fr, inv: bool) {
        let n = input.len().next_power_of_two();
        let log_n = n.trailing_zeros();
        let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);
        let mut pq = vec![Fr::zero(); 1 << max_deg >> 1];
        let twiddle = group_gen.pow([(n >> max_deg) as u64]);
        pq[0] = Fr::one();
        if max_deg > 1 {
            pq[1] = twiddle;
            for i in 2..(1 << max_deg >> 1) {
                pq[i] = pq[i - 1];
                pq[i] *= twiddle;
            }
        }
        let mut omegas = vec![Fr::zero(); 32];
        omegas[0] = *group_gen;
        for i in 1..LOG2_MAX_ELEMENTS {
            omegas[i] = omegas[i - 1].pow([2u64]);
        }
        self.fft_inner(input, &pq, &omegas, log_n);
        if inv {
            let size_inv = Fr::from(n as u64).inverse().unwrap();
            input.par_iter_mut().for_each(|val| *val *= size_inv);
        }
    }

    pub fn fft_precomputed(&self, input: &mut [Fr], group_elems: &[Fr], inv: bool) {
        let n = group_elems.len();
        let log_n = n.trailing_zeros();
        let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);
        let pq = if inv {
            (0..1 << max_deg >> 1)
                .into_par_iter()
                .map(|i| if i == 0 { Fr::one() } else { group_elems[n - (n >> max_deg) * i] })
                .collect::<Vec<_>>()
        } else {
            (0..1 << max_deg >> 1)
                .into_par_iter()
                .map(|i| group_elems[(n >> max_deg) * i])
                .collect::<Vec<_>>()
        };
        let omegas = if inv {
            (0..log_n).into_par_iter().map(|i| group_elems[n - (1 << i)]).collect::<Vec<_>>()
        } else {
            (0..log_n).into_par_iter().map(|i| group_elems[1 << i]).collect::<Vec<_>>()
        };
        self.fft_inner(input, &pq, &omegas, log_n);
        if inv {
            let size_inv = Fr::from(n as u64).inverse().unwrap();
            input.par_iter_mut().for_each(|val| *val *= size_inv);
        }
    }

    pub fn batch_fft_precomputed(&self, input: &mut [Fr], group_elems: &[Fr], m: usize, inv: bool) {
        let n = group_elems.len();
        assert_eq!(input.len(), m * n);
        let log_n = n.trailing_zeros();
        let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);
        let pq = if inv {
            (0..1 << max_deg >> 1)
                .into_par_iter()
                .map(|i| if i == 0 { Fr::one() } else { group_elems[n - (n >> max_deg) * i] })
                .collect::<Vec<_>>()
        } else {
            (0..1 << max_deg >> 1)
                .into_par_iter()
                .map(|i| group_elems[(n >> max_deg) * i])
                .collect::<Vec<_>>()
        };
        let omegas = if inv {
            (0..log_n).into_par_iter().map(|i| group_elems[n - (1 << i)]).collect::<Vec<_>>()
        } else {
            (0..log_n).into_par_iter().map(|i| group_elems[1 << i]).collect::<Vec<_>>()
        };
        self.batch_fft_inner(input, &pq, &omegas, log_n, m);
        if inv {
            let size_inv = Fr::from(n as u64).inverse().unwrap();
            input.par_iter_mut().for_each(|val| *val *= size_inv);
        }
    }
}

#[derive(Default)]
pub struct DomainPrecomputed {
    size: usize,
    size_inv: Fr,
    log_size: u32,
    // pq: Vec<Fr>,
    // pq_inv: Vec<Fr>,
    pub omegas: Vec<Fr>,
    omegas_inv: Vec<Fr>,
}

impl DomainPrecomputed {
    // fn compute_pq(group_gen: Fr, n: usize) -> Vec<Fr> {
    //     let max_deg = cmp::min(MAX_LOG2_RADIX, n.trailing_zeros());
    //     let twiddle = group_gen.pow([(n >> max_deg) as u64]);
    //     let len = 1 << max_deg >> 1;
    //     let mut pq = vec![Fr::zero(); len];
    //     pq[0] = Fr::one();
    //     for i in 1..len {
    //         pq[i] = pq[i - 1] * twiddle;
    //     }
    //     pq
    // }

    fn compute_omegas(group_gen: Fr, log_n: usize) -> Vec<Fr> {
        let mut omegas = vec![Fr::zero(); log_n];
        omegas[0] = group_gen;
        for i in 1..log_n {
            omegas[i] = omegas[i - 1].square();
        }
        omegas
    }

    pub fn new(n: usize) -> Self {
        let n = n.next_power_of_two();
        let group_gen = Fr::get_root_of_unity(n).unwrap();
        let group_gen_inv = group_gen.inverse().unwrap();

        let log_n = n.trailing_zeros();

        Self {
            size: n,
            size_inv: Fr::from(n as u64).inverse().unwrap(),
            log_size: log_n,
            // pq: Self::compute_pq(group_gen, n),
            // pq_inv: Self::compute_pq(group_gen_inv, n),
            omegas: Self::compute_omegas(group_gen, log_n as usize),
            omegas_inv: Self::compute_omegas(group_gen_inv, log_n as usize),
        }
    }
}

pub trait FFTDomain<T> {
    // fn fft(&self, input: &mut T);

    // fn ifft(&self, input: &mut T);

    fn fft_io(&self, input: &mut T);

    fn ifft_oi(&self, input: &mut T);

    fn derange(&self, input: &mut T);

    fn ifft_ii(&self, input: &mut T) {
        self.derange(input);
        self.ifft_oi(input);
    }
}

#[derive(Default)]
pub struct Domain {
    pub n: DomainPrecomputed,
    // c: DomainPrecomputed,
    // r: DomainPrecomputed,
}

impl Domain {
    pub fn new(n: usize) -> Self {
        let n = n.next_power_of_two();

        // let log_n = n.trailing_zeros();

        // let r = 1 << (log_n >> 1);
        // let c = n / r;

        Self {
            n: DomainPrecomputed::new(n),
            // c: DomainPrecomputed::new(c),
            // r: DomainPrecomputed::new(r),
        }
    }

    pub fn from_group_elems(elems: &[Fr]) -> Self {
        let n = elems.len();
        assert!(n.is_power_of_two());
        let log_n = n.trailing_zeros();
        // let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);
        // let pq_len = 1 << max_deg >> 1;
        // let step = n >> max_deg;

        // let r = 1 << (log_n >> 1);
        // let c = n / r;

        Self {
            n: DomainPrecomputed {
                size: n,
                size_inv: Fr::from(n as u64).inverse().unwrap(),
                log_size: log_n,
                // pq: (0..pq_len).into_par_iter().map(|i| elems[step * i]).collect(),
                // pq_inv: (0..pq_len)
                //     .into_par_iter()
                //     .map(|i| if i == 0 { Fr::one() } else { elems[n - step * i] })
                //     .collect(),
                omegas: (0..log_n).into_par_iter().map(|i| elems[1 << i]).collect(),
                omegas_inv: (0..log_n).into_par_iter().map(|i| elems[n - (1 << i)]).collect(),
            },
            // c: DomainPrecomputed::new(c),
            // r: DomainPrecomputed::new(r),
        }
    }

    #[inline]
    pub fn generator(&self) -> Fr {
        self.n.omegas[0]
    }

    #[inline]
    pub fn generator_inv(&self) -> Fr {
        self.n.omegas_inv[0]
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.n.size
    }

    // fn fft_helper(&self, input: &mut [Fr], inv: bool) {
    //     assert_eq!(input.len(), self.n.size);
    //     let mut max_size = usize::MAX;
    //     for device in Device::all().iter() {
    //         max_size = cmp::min(max_size, device.memory() as usize / 4 / size_of::<Fr>());
    //     }
    //     max_size = max_size.next_power_of_two(); // TODO: better upper bound
    //     if input.len() <= max_size {
    //         println!("Input size is small enough to fit in GPU memory. Run in a single pass.");
    //         if inv {
    //             KERNELS[0].lock().unwrap().fft_inner(
    //                 input,
    //                 &self.n.pq_inv,
    //                 &self.n.omegas_inv,
    //                 self.n.log_size,
    //             );
    //             input.par_iter_mut().for_each(|val| *val *= self.n.size_inv);
    //         } else {
    //             KERNELS[0].lock().unwrap().fft_inner(
    //                 input,
    //                 &self.n.pq,
    //                 &self.n.omegas,
    //                 self.n.log_size,
    //             );
    //         }
    //     } else {
    //         println!("Large input. Run in multiple passes using all GPUs.");
    //         let r = self.r.size;
    //         let c = self.c.size;
    //         let log_r = self.r.log_size;
    //         let log_c = self.c.log_size;
    //         let c_pq = if inv { &self.c.pq_inv } else { &self.c.pq };
    //         let c_omegas = if inv { &self.c.omegas_inv } else { &self.c.omegas };
    //         let r_pq = if inv { &self.r.pq_inv } else { &self.r.pq };
    //         let r_omegas = if inv { &self.r.omegas_inv } else { &self.r.omegas };

    //         let mut t = vec![Default::default(); (1 << self.n.log_size) >> 2];
    //         ip_transpose(input, &mut t, c, r);
    //         input.chunks_mut(max_size * KERNELS.len()).for_each(|group| {
    //             KERNELS.par_iter().zip(group.par_chunks_mut(max_size)).for_each(
    //                 |(kernel, chunk)| {
    //                     kernel.lock().unwrap().batch_fft_inner(
    //                         chunk,
    //                         &c_pq,
    //                         &c_omegas,
    //                         log_c,
    //                         chunk.len() / c,
    //                     );
    //                 },
    //             );
    //         });
    //         let g = if inv { self.generator_inv() } else { self.generator() };
    //         let h = if inv { self.c.size_inv } else { Fr::one() };
    //         input.par_chunks_mut(c).enumerate().for_each(|(i, chunk)| {
    //             let s = g.pow([i as u64]);
    //             let mut t = h;
    //             for j in chunk {
    //                 *j *= t;
    //                 t *= s;
    //             }
    //         });
    //         ip_transpose(input, &mut t, r, c);
    //         input.chunks_mut(max_size * KERNELS.len()).for_each(|group| {
    //             KERNELS.par_iter().zip(group.par_chunks_mut(max_size)).for_each(
    //                 |(kernel, chunk)| {
    //                     kernel.lock().unwrap().batch_fft_inner(
    //                         chunk,
    //                         &r_pq,
    //                         &r_omegas,
    //                         log_r,
    //                         chunk.len() / r,
    //                     );
    //                 },
    //             );
    //         });
    //         if inv {
    //             input.par_iter_mut().for_each(|val| *val *= self.r.size_inv);
    //         }
    //         ip_transpose(input, &mut t, c, r);
    //     }
    // }

    fn fft_io_helper(&self, input: &mut [Fr]) {
        assert_eq!(input.len(), self.n.size);

        let mut max_size = usize::MAX;
        for device in Device::all().iter() {
            max_size = cmp::min(max_size, device.memory() as usize / 2 / size_of::<Fr>());
        }
        max_size = max_size.next_power_of_two();

        let m = max_size / 2;
        let n = self.n.size;
        let mut gap = n / 2;
        let mut num_chunks = 1;

        while gap > m {
            for i in (0..n / 2).step_by(m * KERNELS.len()) {
                (i..min(i + m * KERNELS.len(), n / 2))
                    .into_par_iter()
                    .step_by(m)
                    .zip(KERNELS.par_iter())
                    .for_each(|(i, kernel)| {
                        let offset = i % gap;
                        let l_start = 2 * i - offset;
                        let l_end = l_start + m;
                        let r_start = l_start + gap;
                        let r_end = r_start + m;
                        kernel.lock().unwrap().butterfly_io2(
                            unsafe { &mut *(&input[l_start..l_end] as *const _ as *mut _) },
                            unsafe { &mut *(&input[r_start..r_end] as *const _ as *mut _) },
                            &self.n.omegas,
                            num_chunks,
                            offset,
                        );
                    });
            }
            gap /= 2;
            num_chunks *= 2;
        }

        input.chunks_mut(max_size * KERNELS.len()).for_each(|group| {
            KERNELS.par_iter().zip(group.par_chunks_mut(max_size)).for_each(|(kernel, chunk)| {
                kernel.lock().unwrap().butterfly_io3(chunk, n, &self.n.omegas);
            });
        });
    }

    fn ifft_oi_helper(&self, input: &mut [Fr]) {
        assert_eq!(input.len(), self.n.size);

        let mut max_size = usize::MAX;
        for device in Device::all().iter() {
            max_size = cmp::min(max_size, device.memory() as usize / 2 / size_of::<Fr>());
        }
        max_size = max_size.next_power_of_two();

        let m = max_size / 2;
        let n = self.n.size;
        let mut gap = m * 2;
        let mut num_chunks = n / 2 / gap;

        input.chunks_mut(max_size * KERNELS.len()).for_each(|group| {
            KERNELS.par_iter().zip(group.par_chunks_mut(max_size)).for_each(|(kernel, chunk)| {
                kernel.lock().unwrap().butterfly_oi3(chunk, n, &self.n.omegas_inv);
            });
        });

        while gap < n {
            for i in (0..n / 2).step_by(m * KERNELS.len()) {
                (i..min(i + m * KERNELS.len(), n / 2))
                    .into_par_iter()
                    .step_by(m)
                    .zip(KERNELS.par_iter())
                    .for_each(|(i, kernel)| {
                        let offset = i % gap;
                        let l_start = 2 * i - offset;
                        let l_end = l_start + m;
                        let r_start = l_start + gap;
                        let r_end = r_start + m;
                        kernel.lock().unwrap().butterfly_oi2(
                            unsafe { &mut *(&input[l_start..l_end] as *const _ as *mut _) },
                            unsafe { &mut *(&input[r_start..r_end] as *const _ as *mut _) },
                            &self.n.omegas_inv,
                            num_chunks,
                            offset,
                        );
                    });
            }
            gap *= 2;
            num_chunks /= 2;
        }
        input.par_iter_mut().for_each(|val| *val *= self.n.size_inv);
    }
}

impl FFTDomain<Vec<Fr>> for Domain {
    // fn fft(&self, input: &mut Vec<Fr>) {
    //     input.resize(self.size(), Default::default());
    //     self.fft_helper(input, false)
    // }

    // fn ifft(&self, input: &mut Vec<Fr>) {
    //     input.resize(self.size(), Default::default());
    //     self.fft_helper(input, true);
    // }

    fn fft_io(&self, input: &mut Vec<Fr>) {
        input.resize(self.size(), Default::default());
        self.fft_io_helper(input);
    }

    fn ifft_oi(&self, input: &mut Vec<Fr>) {
        input.resize(self.size(), Default::default());
        self.ifft_oi_helper(input);
    }

    fn derange(&self, input: &mut Vec<Fr>) {
        for idx in 1..(input.len() as u64 - 1) {
            let ridx = idx.reverse_bits() >> (64 - self.n.log_size);
            if idx < ridx {
                input.swap(idx as usize, ridx as usize);
            }
        }
    }
}

impl FFTDomain<MutMmap<Fr>> for Domain {
    // fn fft(&self, input: &mut MutMmap<Fr>) {
    //     self.fft_helper(input, false)
    // }

    // fn ifft(&self, input: &mut MutMmap<Fr>) {
    //     self.fft_helper(input, true)
    // }

    fn fft_io(&self, input: &mut MutMmap<Fr>) {
        self.fft_io_helper(input);
    }

    fn ifft_oi(&self, input: &mut MutMmap<Fr>) {
        self.ifft_oi_helper(input);
    }

    fn derange(&self, input: &mut MutMmap<Fr>) {
        for idx in 1..(input.len() as u64 - 1) {
            let ridx = idx.reverse_bits() >> (64 - self.n.log_size);
            if idx < ridx {
                input.swap(idx as usize, ridx as usize);
            }
        }
    }
}

pub trait MSM
where
    Self: AsRef<[G1Affine]>,
{
    fn var_msm(&self, exps: &[Fr]) -> G1Projective {
        let chunk_size = if exps.len() % KERNELS.len() == 0 {
            exps.len() / KERNELS.len()
        } else {
            exps.len() / KERNELS.len() + 1
        };
        KERNELS
            .par_iter()
            .zip(self.as_ref().par_chunks(chunk_size).zip(exps.par_chunks(chunk_size)))
            .map(|(kernel, (bases, exps))| kernel.lock().unwrap().multiexp(bases, exps))
            .sum()
    }
}

impl MSM for &[G1Affine] {}
impl MSM for Mmap<G1Affine> {}

pub static KERNELS: Lazy<Vec<Mutex<Kernel>>> = Lazy::new(|| {
    Device::all()
        .iter()
        .enumerate()
        .filter(|(i, _)| !GPU_CONFIG.disabled_ids.contains(i))
        .map(|(_, device)| Mutex::new(Kernel::create(include_bytes!("./cl/lib.fatbin"), device)))
        .collect()
});
