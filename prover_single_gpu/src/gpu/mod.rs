pub mod threadpool;

use std::cmp;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, One, PrimeField, Zero};
use rust_gpu_tools::{cuda, program_closures, Device, GPUError, LocalBuffer, Program};
use yastl::Scope;

use crate::gpu::threadpool::{Worker, THREAD_POOL};

/// On the GPU, the exponents are split into windows, this is the maximum number
/// of such windows.
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

/// The number of units the work is split into. One unit will result in one CUDA
/// thread.
///
/// Based on empirical results, it turns out that on Nvidia devices with the
/// Ampere architecture, it's faster to use two times the number of work units.
const fn work_units(compute_units: u32, compute_capabilities: Option<(u32, u32)>) -> usize {
    match compute_capabilities {
        Some((AMPERE, _)) => LOCAL_WORK_SIZE * compute_units as usize * 2,
        _ => LOCAL_WORK_SIZE * compute_units as usize,
    }
}

/// Multiexp kernel for a single GPU.
pub struct SingleKernel {
    program: Program,
    /// The number of exponentiations the GPU can handle in a single execution
    /// of the kernel.
    n: usize,
    /// The number of units the work is split into. It will results in this
    /// amount of threads on the GPU.
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
/// It's the actual bytes size it needs in memory, not it's theoratical bit
/// size.
fn exp_size() -> usize {
    std::mem::size_of::<<Fr as PrimeField>::BigInt>()
}

impl SingleKernel {
    /// Create a new Multiexp kernel instance for a device.
    ///
    /// The `maybe_abort` function is called when it is possible to abort the
    /// computation, without leaving the GPU in a weird state. If that
    /// function returns `true`, execution is aborted.
    pub fn create(binary: &[u8], device: &Device) -> Self {
        let program = Program::Cuda(
            cuda::Program::from_bytes(device.cuda_device().unwrap(), binary).unwrap(),
        );
        let mem = device.memory();
        let compute_units = device.compute_units();
        let compute_capability = device.compute_capability();
        let work_units = work_units(compute_units, compute_capability);
        let chunk_size = calc_chunk_size(mem, work_units);

        SingleKernel {
            program,
            n: chunk_size,
            work_units,
        }
    }

    /// Run the actual multiexp computation on the GPU.
    ///
    /// The number of `bases` and `exponents` are determined by
    /// [`SingleMultiexpKernel`]`::n`, this means that it is guaranteed that
    /// this amount of calculations fit on the GPU this kernel is
    /// running on.
    pub fn multiexp(
        &self,
        bases: &[G1Affine],
        exponents: &[<Fr as PrimeField>::BigInt],
    ) -> G1Projective {
        assert_eq!(bases.len(), exponents.len());

        let window_size = self.calc_window_size(bases.len());
        // windows_size * num_windows needs to be >= 256 in order for the kernel to work
        // correctly.
        let num_windows = div_ceil(256, window_size);
        let num_groups = self.work_units / num_windows;
        let bucket_len = 1 << window_size;

        // Each group will have `num_windows` threads and as there are `num_groups`
        // groups, there will be `num_groups` * `num_windows` threads in total.
        // Each thread will use `num_groups` * `num_windows` * `bucket_len` buckets.

        let closures = program_closures!(|program, _arg| -> Result<Vec<G1Projective>, GPUError> {
            let base_buffer = program.create_buffer_from_slice(bases)?;
            let exp_buffer = program.create_buffer_from_slice(exponents)?;

            // It is safe as the GPU will initialize that buffer
            let bucket_buffer =
                unsafe { program.create_buffer::<G1Projective>(self.work_units * bucket_len)? };
            // It is safe as the GPU will initialize that buffer
            let result_buffer = unsafe { program.create_buffer::<G1Projective>(self.work_units)? };

            // The global work size follows CUDA's definition and is the number of
            // `LOCAL_WORK_SIZE` sized thread groups.
            let global_work_size = div_ceil(num_windows * num_groups, LOCAL_WORK_SIZE);

            let kernel_name = format!("multiexp");
            let kernel = program.create_kernel(&kernel_name, global_work_size, LOCAL_WORK_SIZE)?;

            kernel
                .arg(&base_buffer)
                .arg(&bucket_buffer)
                .arg(&result_buffer)
                .arg(&exp_buffer)
                .arg(&(bases.len() as u32))
                .arg(&(num_groups as u32))
                .arg(&(num_windows as u32))
                .arg(&(window_size as u32))
                .run()?;

            let mut results = vec![G1Projective::zero(); self.work_units];
            program.read_into_buffer(&result_buffer, &mut results)?;

            Ok(results)
        });

        let results = self.program.run(closures, ()).unwrap();

        // Using the algorithm below, we can calculate the final result by accumulating
        // the results of those `NUM_GROUPS` * `NUM_WINDOWS` threads.
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

    /// Calculates the window size, based on the given number of terms.
    ///
    /// For best performance, the window size is reduced, so that maximum
    /// parallelism is possible. If you e.g. have put only a subset of the
    /// terms into the GPU memory, then a smaller window size leads to more
    /// windows, hence more units to work on, as we split the work into
    /// `num_windows * num_groups`.
    fn calc_window_size(&self, num_terms: usize) -> usize {
        // The window size was determined by running the `gpu_multiexp_consistency` test
        // and looking at the resulting numbers.
        let window_size = ((div_ceil(num_terms, self.work_units) as f64).log2() as usize) + 2;
        std::cmp::min(window_size, MAX_WINDOW_SIZE)
    }

    /// Performs FFT on `input`
    /// * `omega` - Special value `omega` is used for FFT over finite-fields
    /// * `log_n` - Specifies log2 of number of elements
    pub fn radix_fft(&mut self, input: &mut [Fr], omega: &Fr, log_n: u32) {
        let closures = program_closures!(|program, input: &mut [Fr]| -> Result<(), GPUError> {
            let n = 1 << log_n;
            // All usages are safe as the buffers are initialized from either the host or
            // the GPU before they are read.
            let mut src_buffer = unsafe { program.create_buffer::<Fr>(n)? };
            let mut dst_buffer = unsafe { program.create_buffer::<Fr>(n)? };
            // The precalculated values pq` and `omegas` are valid for radix degrees up to
            // `max_deg`
            let max_deg = cmp::min(MAX_LOG2_RADIX, log_n);

            // Precalculate:
            // [omega^(0/(2^(deg-1))), omega^(1/(2^(deg-1))), ...,
            // omega^((2^(deg-1)-1)/(2^(deg-1)))]
            let mut pq = vec![Fr::zero(); 1 << max_deg >> 1];
            let twiddle = omega.pow([(n >> max_deg) as u64]);
            pq[0] = Fr::one();
            if max_deg > 1 {
                pq[1] = twiddle;
                for i in 2..(1 << max_deg >> 1) {
                    pq[i] = pq[i - 1];
                    pq[i] *= twiddle;
                }
            }
            let pq_buffer = program.create_buffer_from_slice(&pq)?;

            // Precalculate [omega, omega^2, omega^4, omega^8, ..., omega^(2^31)]
            let mut omegas = vec![Fr::zero(); 32];
            omegas[0] = *omega;
            for i in 1..LOG2_MAX_ELEMENTS {
                omegas[i] = omegas[i - 1].pow([2u64]);
            }
            let omegas_buffer = program.create_buffer_from_slice(&omegas)?;

            program.write_from_buffer(&mut src_buffer, &*input)?;
            // Specifies log2 of `p`, (http://www.bealto.com/gpu-fft_group-1.html)
            let mut log_p = 0u32;
            // Each iteration performs a FFT round
            while log_p < log_n {
                // 1=>radix2, 2=>radix4, 3=>radix8, ...
                let deg = cmp::min(max_deg, log_n - log_p);

                let n = 1u32 << log_n;
                let local_work_size = 1 << cmp::min(deg - 1, MAX_LOG2_LOCAL_WORK_SIZE);
                let global_work_size = n >> deg;
                let kernel_name = format!("radix_fft");
                let kernel = program.create_kernel(
                    &kernel_name,
                    global_work_size as usize,
                    local_work_size as usize,
                )?;
                kernel
                    .arg(&src_buffer)
                    .arg(&dst_buffer)
                    .arg(&pq_buffer)
                    .arg(&omegas_buffer)
                    .arg(&LocalBuffer::<Fr>::new(1 << deg))
                    .arg(&n)
                    .arg(&log_p)
                    .arg(&deg)
                    .arg(&max_deg)
                    .run()?;

                log_p += deg;
                std::mem::swap(&mut src_buffer, &mut dst_buffer);
            }

            program.read_into_buffer(&src_buffer, input)?;

            Ok(())
        });

        self.program.run(closures, input).unwrap()
    }
}

/// A struct that containts several multiexp kernels for different devices.
pub struct MultiKernel {
    kernels: Vec<SingleKernel>,
}

impl MultiKernel {
    /// Create new kernels, one for each given device.
    pub fn create(binary: &[u8]) -> Self {
        let kernels: Vec<_> = Device::all()
            .iter()
            .filter_map(|device| {
                let kernel = SingleKernel::create(binary, device);
                Some(kernel)
            })
            .collect();

        assert!(!kernels.is_empty());
        MultiKernel { kernels }
    }

    /// Calculate multiexp on all available GPUs.
    ///
    /// It needs to run within a [`yastl::Scope`]. This method usually isn't
    /// called directly, use [`MultiexpKernel::multiexp`] instead.
    fn parallel_multiexp<'s>(
        &'s mut self,
        scope: &Scope<'s>,
        bases: &'s [G1Affine],
        exps: &'s [<Fr as PrimeField>::BigInt],
        results: &'s mut [G1Projective],
    ) {
        let num_devices = self.kernels.len();
        let num_exps = exps.len();
        // The maximum number of exponentiations per device.
        let chunk_size = ((num_exps as f64) / (num_devices as f64)).ceil() as usize;

        for (((bases, exps), kern), result) in bases
            .chunks(chunk_size)
            .zip(exps.chunks(chunk_size))
            // NOTE vmx 2021-11-17: This doesn't need to be a mutable iterator. But when it isn't
            // there will be errors that the OpenCL CommandQueue cannot be shared between threads
            // safely.
            .zip(self.kernels.iter_mut())
            .zip(results.iter_mut())
        {
            scope.execute(move || {
                let mut acc = G1Projective::default();
                for (bases, exps) in bases.chunks(kern.n).zip(exps.chunks(kern.n)) {
                    acc += &kern.multiexp(bases, exps);
                }
                *result = acc;
            });
        }
    }

    /// Calculate multiexp.
    ///
    /// This is the main entry point.
    pub fn multiexp(
        &mut self,
        pool: &Worker,
        bases_arc: &[G1Affine],
        exps: &[<Fr as PrimeField>::BigInt],
        skip: usize,
    ) -> G1Projective {
        // Bases are skipped by `self.1` elements, when converted from (Arc<Vec<G>>,
        // usize) to Source https://github.com/zkcrypto/bellman/blob/10c5010fd9c2ca69442dc9775ea271e286e776d8/src/multiexp.rs#L38
        let bases = &bases_arc[skip..(skip + exps.len())];
        let exps = &exps[..];

        let mut results = Vec::new();

        pool.scoped(|s| {
            results = vec![G1Projective::default(); self.kernels.len()];
            self.parallel_multiexp(s, bases, exps, &mut results);
        });

        let mut acc = G1Projective::default();
        for r in results {
            acc += &r;
        }

        acc
    }

    /// Returns the number of kernels (one per device).
    pub fn num_kernels(&self) -> usize {
        self.kernels.len()
    }

    /// Performs FFT on `inputs`
    /// * `omega` - Special value `omega` is used for FFT over finite-fields
    /// * `log_n` - Specifies log2 of number of elements
    ///
    /// Uses all available GPUs to distribute the work.
    pub fn radix_fft_many(&mut self, inputs: &mut [&mut [Fr]], omegas: &[Fr], log_ns: &[u32]) {
        let n = inputs.len();
        let num_devices = self.kernels.len();
        let chunk_size = ((n as f64) / (num_devices as f64)).ceil() as usize;

        THREAD_POOL.scoped(|s| {
            for (((inputs, omegas), log_ns), kern) in inputs
                .chunks_mut(chunk_size)
                .zip(omegas.chunks(chunk_size))
                .zip(log_ns.chunks(chunk_size))
                .zip(self.kernels.iter_mut())
            {
                s.execute(move || {
                    for ((input, omega), log_n) in
                        inputs.iter_mut().zip(omegas.iter()).zip(log_ns.iter())
                    {
                        kern.radix_fft(input, omega, *log_n);
                    }
                });
            }
        });
    }

    pub fn radix_fft(&mut self, input: &mut [Fr], omega: &Fr, log_n: u32) {
        self.kernels[0].radix_fft(input, omega, log_n);
    }
}
