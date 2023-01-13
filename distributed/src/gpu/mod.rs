// Copyright Filecoin Project
//
// This file is adapted from the ec-gpu library, which is licensed under either of the following licenses:
// - Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
// - MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
//
// See https://github.com/filecoin-project/ec-gpu for more information.

use std::{
    cmp::{self, max, min},
    ffi::{c_void, CString},
    mem::size_of,
};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{FftField, Field, One, Zero};
use once_cell::sync::Lazy;
use rayon::{
    prelude::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::{ParallelSlice, ParallelSliceMut},
};
use rustacuda::{
    error::CudaResult,
    memory::AsyncCopyDestination,
    prelude::{DeviceBuffer, Module},
    stream::{Stream, StreamFlags},
};

pub mod device;

use self::device::Device;
use crate::{
    config::GPU_CONFIG,
    gpu::device::DEVICES,
    mmap::{Mmap, MutMmap},
    utils::CastSlice,
};

pub trait KernelArgument {
    /// Converts into a C void pointer.
    fn as_c_void(&self) -> *mut c_void;
}

impl<T> KernelArgument for DeviceBuffer<T> {
    fn as_c_void(&self) -> *mut c_void {
        self as *const _ as _
    }
}

impl KernelArgument for u32 {
    fn as_c_void(&self) -> *mut c_void {
        self as *const _ as _
    }
}

/// On the GPU, the exponents are split into windows, this is the maximum number of such windows.
const MAX_WINDOW_SIZE: usize = 10;
/// In CUDA this is the number of blocks per grid (grid size).
const LOCAL_WORK_SIZE: usize = 128;
/// Let 20% of GPU memory be free, this is an arbitrary value.
const MEMORY_PADDING: f64 = 0.2f64;
/// The Nvidia Ampere architecture is compute capability major version 8.
const AMPERE: u32 = 8;

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
const fn work_units(compute_units: u32, compute_capabilities: (u32, u32)) -> usize {
    match compute_capabilities {
        (AMPERE, _) => LOCAL_WORK_SIZE * compute_units as usize * 2,
        _ => LOCAL_WORK_SIZE * compute_units as usize,
    }
}

pub struct Kernel {
    /// The number of exponentiations the GPU can handle in a single execution of the kernel.
    n: usize,
    /// The number of units the work is split into. It will results in this amount of threads on
    /// the GPU.
    work_units: usize,
    module: Module,
    stream: Stream,
    device: &'static Device,
}

unsafe impl Send for Kernel {}
unsafe impl Sync for Kernel {}

/// Calculates the maximum number of terms that can be put onto the GPU memory.
fn calc_chunk_size(mem: usize, work_units: usize) -> usize {
    let aff_size = size_of::<G1Affine>();
    assert_eq!(aff_size, 104);
    let exp_size = size_of::<Fr>();
    let proj_size = size_of::<G1Projective>();

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

fn write_to_device<T>(input: &[T], stream: &Stream) -> CudaResult<DeviceBuffer<u8>> {
    unsafe {
        let buffer = input.cast::<u8>();
        let mut device_buffer = DeviceBuffer::<u8>::uninitialized(buffer.len())?;
        device_buffer.async_copy_from(buffer, stream)?;
        Ok(device_buffer)
    }
}

fn read_from_device<T>(output: &mut [T], buf: DeviceBuffer<u8>, stream: &Stream) -> CudaResult<()> {
    unsafe {
        let buffer = output.cast_mut::<u8>();
        buf.async_copy_to(buffer, stream)?;
    }
    Ok(())
}

impl Kernel {
    /// Create a new Multiexp kernel instance for a device.
    ///
    /// The `maybe_abort` function is called when it is possible to abort the computation, without
    /// leaving the GPU in a weird state. If that function returns `true`, execution is aborted.
    pub fn create(binary: &[u8], device: &'static Device) -> Self {
        rustacuda::context::CurrentContext::set_current(&device.context).unwrap();
        let module = rustacuda::module::Module::load_from_bytes(binary).unwrap();
        let stream = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();
        rustacuda::context::ContextStack::pop().expect("Cannot remove context.");

        let mem = device.memory;
        let compute_units = device.compute_units;
        let compute_capability = device.compute_capability;
        let work_units = work_units(compute_units, compute_capability);
        let chunk_size = calc_chunk_size(mem, work_units);

        Kernel { module, stream, n: chunk_size, work_units, device }
    }

    /// Run the actual multiexp computation on the GPU.
    ///
    /// The number of `bases` and `exponents` are determined by [`SingleMultiexpKernel`]`::n`, this
    /// means that it is guaranteed that this amount of calculations fit on the GPU this kernel is
    /// running on.
    fn multiexp_inner(&self, bases: &[G1Affine], exponents: &[Fr]) -> CudaResult<G1Projective> {
        let stream = &self.stream;

        let len = min(bases.len(), exponents.len());

        let window_size = self.calc_window_size(len);
        // windows_size * num_windows needs to be >= 256 in order for the kernel to work correctly.
        let num_windows = div_ceil(256, window_size);
        let num_groups = self.work_units / num_windows;
        let bucket_len = 1 << window_size;

        // Each group will have `num_windows` threads and as there are `num_groups` groups, there will
        // be `num_groups` * `num_windows` threads in total.
        // Each thread will use `num_groups` * `num_windows` * `bucket_len` buckets.

        rustacuda::context::CurrentContext::set_current(&self.device.context)?;

        let bucket_buffer = unsafe {
            DeviceBuffer::<u8>::uninitialized(
                self.work_units * bucket_len * std::mem::size_of::<G1Projective>(),
            )?
        };
        let result_buffer = unsafe {
            DeviceBuffer::<u8>::uninitialized(
                self.work_units * std::mem::size_of::<G1Projective>(),
            )?
        };
        let base_buffer = write_to_device(bases, stream)?;
        let exp_buffer = write_to_device(exponents, stream)?;

        let function = self.module.get_function(&CString::new("multiexp").unwrap())?;

        let local_work_size = LOCAL_WORK_SIZE;
        let global_work_size = div_ceil(num_windows * num_groups, LOCAL_WORK_SIZE);

        unsafe {
            stream.launch(
                &function,
                global_work_size as u32,
                local_work_size as u32,
                0,
                &[
                    base_buffer.as_c_void(),
                    bucket_buffer.as_c_void(),
                    result_buffer.as_c_void(),
                    exp_buffer.as_c_void(),
                    (len as u32).as_c_void(),
                    (num_groups as u32).as_c_void(),
                    (num_windows as u32).as_c_void(),
                    (window_size as u32).as_c_void(),
                ],
            )?;
        };

        let mut results = vec![G1Projective::zero(); self.work_units];
        read_from_device(&mut results, result_buffer, stream)?;

        stream.synchronize()?;

        rustacuda::context::ContextStack::pop()?;

        // Using the algorithm below, we can calculate the final result by accumulating the results
        // of those `NUM_GROUPS` * `NUM_WINDOWS` threads.
        let mut acc = G1Projective::default();
        let mut bits = 0;
        let exp_bits = size_of::<Fr>() * 8;
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

        Ok(acc)
    }

    pub fn multiexp(&self, bases: &[G1Affine], exps: &[Fr]) -> CudaResult<G1Projective> {
        let n = self.n;
        let mut result = G1Projective::default();
        for (bases, exps) in bases.chunks(n).zip(exps.chunks(n)) {
            result += self.multiexp_inner(bases, exps)?;
        }

        Ok(result)
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

    pub fn butterfly_io_update(
        &self,
        x: &mut [Fr],
        y: &mut [Fr],
        omegas: &[Fr],
        num_chunks: usize,
        offset: usize,
    ) -> CudaResult<()> {
        let stream = &self.stream;

        rustacuda::context::CurrentContext::set_current(&self.device.context)?;

        let x_buffer = write_to_device(x, stream)?;
        let y_buffer = write_to_device(y, stream)?;
        let omegas_buffer = write_to_device(omegas, stream)?;
        let function = self.module.get_function(&CString::new("butterfly_io_update").unwrap())?;

        let local_work_size = min(x.len(), 1024);
        let global_work_size = max(x.len() / 1024, 1);

        unsafe {
            stream.launch(
                &function,
                global_work_size as u32,
                local_work_size as u32,
                0,
                &[
                    x_buffer.as_c_void(),
                    y_buffer.as_c_void(),
                    omegas_buffer.as_c_void(),
                    (num_chunks as u32).as_c_void(),
                    (offset as u32).as_c_void(),
                ],
            )?;
        };

        read_from_device(x, x_buffer, stream)?;
        read_from_device(y, y_buffer, stream)?;

        stream.synchronize()?;

        rustacuda::context::ContextStack::pop()?;
        Ok(())
    }

    pub fn butterfly_io_finalize(
        &self,
        input: &mut [Fr],
        n: usize,
        omegas: &[Fr],
    ) -> CudaResult<()> {
        let stream = &self.stream;

        rustacuda::context::CurrentContext::set_current(&self.device.context)?;

        let input_buffer = write_to_device(input, stream)?;
        let omegas_buffer = write_to_device(omegas, stream)?;
        let function = self.module.get_function(&CString::new("butterfly_io_finalize").unwrap())?;

        let mut gap = input.len() / 2;
        let t = 512;
        while gap > 0 {
            let local_work_size = min(t, gap);
            let global_work_size = input.len() / (2 * local_work_size);

            unsafe {
                stream.launch(
                    &function,
                    global_work_size as u32,
                    local_work_size as u32,
                    (2 * t * size_of::<Fr>()) as u32,
                    &[
                        input_buffer.as_c_void(),
                        (n as u32).as_c_void(),
                        omegas_buffer.as_c_void(),
                        (gap as u32).as_c_void(),
                    ],
                )?;
            };

            gap /= 2 * t;
        }
        read_from_device(input, input_buffer, stream)?;

        stream.synchronize()?;

        rustacuda::context::ContextStack::pop()?;
        Ok(())
    }

    pub fn butterfly_oi_update(
        &self,
        x: &mut [Fr],
        y: &mut [Fr],
        omegas: &[Fr],
        num_chunks: usize,
        offset: usize,
    ) -> CudaResult<()> {
        let stream = &self.stream;

        rustacuda::context::CurrentContext::set_current(&self.device.context)?;

        let x_buffer = write_to_device(x, stream)?;
        let y_buffer = write_to_device(y, stream)?;
        let omegas_buffer = write_to_device(omegas, stream)?;
        let function = self.module.get_function(&CString::new("butterfly_oi_update").unwrap())?;

        let local_work_size = min(x.len(), 1024);
        let global_work_size = max(x.len() / 1024, 1);

        unsafe {
            stream.launch(
                &function,
                global_work_size as u32,
                local_work_size as u32,
                0,
                &[
                    x_buffer.as_c_void(),
                    y_buffer.as_c_void(),
                    omegas_buffer.as_c_void(),
                    (num_chunks as u32).as_c_void(),
                    (offset as u32).as_c_void(),
                ],
            )?;
        };

        read_from_device(x, x_buffer, stream)?;
        read_from_device(y, y_buffer, stream)?;

        stream.synchronize()?;

        rustacuda::context::ContextStack::pop()?;
        Ok(())
    }

    pub fn butterfly_oi_finalize(
        &self,
        input: &mut [Fr],
        n: usize,
        omegas: &[Fr],
    ) -> CudaResult<()> {
        let stream = &self.stream;

        rustacuda::context::CurrentContext::set_current(&self.device.context)?;

        let input_buffer = write_to_device(input, stream)?;
        let omegas_buffer = write_to_device(omegas, stream)?;
        let function = self.module.get_function(&CString::new("butterfly_oi_finalize").unwrap())?;

        let mut gap = 1;
        let t = 512;
        while gap < input.len() {
            let local_work_size = min(t, input.len() / (2 * gap));
            let global_work_size = input.len() / (2 * local_work_size);

            unsafe {
                stream.launch(
                    &function,
                    global_work_size as u32,
                    local_work_size as u32,
                    (2 * t * size_of::<Fr>()) as u32,
                    &[
                        input_buffer.as_c_void(),
                        (n as u32).as_c_void(),
                        omegas_buffer.as_c_void(),
                        (gap as u32).as_c_void(),
                    ],
                )?;
            };

            gap *= 2 * t;
        }
        read_from_device(input, input_buffer, stream)?;

        stream.synchronize()?;

        rustacuda::context::ContextStack::pop()?;
        Ok(())
    }
}

#[derive(Default)]
pub struct DomainPrecomputed {
    size: usize,
    size_inv: Fr,
    log_size: u32,
    // pq: Vec<Fr>,
    // pq_inv: Vec<Fr>,
    omegas: Vec<Fr>,
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

    fn compute_omegas(group_gen: Fr) -> Vec<Fr> {
        let mut r = {
            let mut base_powers = vec![Fr::one()];
            for _ in 1..(1 << 16) {
                base_powers.push(group_gen * base_powers.last().unwrap());
            }
            base_powers
        };
        r.extend_from_slice(
            &r.par_iter()
                .map(|i| {
                    let mut res = *i;
                    for _ in 0..16 {
                        res *= res;
                    }
                    res
                })
                .collect::<Vec<_>>(),
        );
        r
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
            omegas: Self::compute_omegas(group_gen),
            omegas_inv: Self::compute_omegas(group_gen_inv),
        }
    }
}

pub trait FFTDomain<T> {
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
    n: DomainPrecomputed,
}

impl Domain {
    pub fn new(n: usize) -> Self {
        Self { n: DomainPrecomputed::new(n.next_power_of_two()) }
    }

    #[inline]
    pub fn element(&self, e: usize) -> Fr {
        self.n.omegas[e & 65535] * self.n.omegas[(e >> 16) + 65536]
    }

    #[inline]
    pub fn generator(&self) -> Fr {
        self.n.omegas[1]
    }

    #[inline]
    pub fn generator_inv(&self) -> Fr {
        self.n.omegas_inv[1]
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.n.size
    }

    #[inline]
    pub fn omegas(&self) -> &[Fr] {
        &self.n.omegas
    }

    fn fft_io_helper(&self, input: &mut [Fr]) {
        assert_eq!(input.len(), self.n.size);

        let mut max_size = usize::MAX;
        for device in DEVICES.0.iter() {
            max_size = cmp::min(max_size, device.memory / 2 / size_of::<Fr>());
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
                        kernel
                            .butterfly_io_update(
                                unsafe { &mut *(&input[l_start..l_end] as *const _ as *mut _) },
                                unsafe { &mut *(&input[r_start..r_end] as *const _ as *mut _) },
                                &self.n.omegas,
                                num_chunks,
                                offset,
                            )
                            .unwrap();
                    });
            }
            gap /= 2;
            num_chunks *= 2;
        }

        input.chunks_mut(max_size * KERNELS.len()).for_each(|group| {
            KERNELS.par_iter().zip(group.par_chunks_mut(max_size)).for_each(|(kernel, chunk)| {
                kernel.butterfly_io_finalize(chunk, n, &self.n.omegas).unwrap();
            });
        });
    }

    fn ifft_oi_helper(&self, input: &mut [Fr]) {
        assert_eq!(input.len(), self.n.size);

        let mut max_size = usize::MAX;
        for device in DEVICES.0.iter() {
            max_size = cmp::min(max_size, device.memory / 2 / size_of::<Fr>());
        }
        max_size = max_size.next_power_of_two();

        let m = max_size / 2;
        let n = self.n.size;
        let mut gap = m * 2;
        let mut num_chunks = n / 2 / gap;

        input.chunks_mut(max_size * KERNELS.len()).for_each(|group| {
            KERNELS.par_iter().zip(group.par_chunks_mut(max_size)).for_each(|(kernel, chunk)| {
                kernel.butterfly_oi_finalize(chunk, n, &self.n.omegas_inv).unwrap();
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
                        kernel
                            .butterfly_oi_update(
                                unsafe { &mut *(&input[l_start..l_end] as *const _ as *mut _) },
                                unsafe { &mut *(&input[r_start..r_end] as *const _ as *mut _) },
                                &self.n.omegas_inv,
                                num_chunks,
                                offset,
                            )
                            .unwrap();
                    });
            }
            gap *= 2;
            num_chunks /= 2;
        }
        input.par_iter_mut().for_each(|val| *val *= self.n.size_inv);
    }
}

impl FFTDomain<Vec<Fr>> for Domain {
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

pub trait MSM: AsRef<[G1Affine]> {
    fn var_msm(&self, exps: &[Fr]) -> G1Projective {
        let chunk_size = if exps.len() % KERNELS.len() == 0 {
            exps.len() / KERNELS.len()
        } else {
            exps.len() / KERNELS.len() + 1
        };
        KERNELS
            .par_iter()
            .zip(self.as_ref().par_chunks(chunk_size).zip(exps.par_chunks(chunk_size)))
            .map(|(kernel, (bases, exps))| kernel.multiexp(bases, exps).unwrap())
            .sum()
    }
}

impl MSM for &[G1Affine] {}
impl MSM for Mmap<G1Affine> {}

pub static KERNELS: Lazy<Vec<Kernel>> = Lazy::new(|| {
    DEVICES
        .0
        .iter()
        .enumerate()
        .filter(|(i, _)| !GPU_CONFIG.excluded_ids.contains(i))
        .map(|(_, device)| Kernel::create(include_bytes!("./cl/lib.fatbin"), device))
        .collect()
});
