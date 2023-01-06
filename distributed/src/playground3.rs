use ark_ff::FftField;
use ark_std::vec::Vec;
use rayon::prelude::*;

#[inline]
fn bitrev(a: u64, log_len: u32) -> u64 {
    a.reverse_bits() >> (64 - log_len)
}

pub fn derange<T>(xi: &mut [T], log_len: u32) {
    for idx in 1..(xi.len() as u64 - 1) {
        let ridx = bitrev(idx, log_len);
        if idx < ridx {
            xi.swap(idx as usize, ridx as usize);
        }
    }
}

pub fn fft_helper_in_place<T: FftField>(x_s: &mut [T], group_gen: T) {
    io_helper(x_s, group_gen);
}

pub fn ifft_helper_in_place<T: FftField>(x_s: &mut [T], group_gen_inv: T) {
    oi_helper(x_s, group_gen_inv);
    let size_inv = T::from(x_s.len() as u64).inverse().unwrap();
    x_s.par_iter_mut().for_each(|val| *val *= size_inv);
}

pub(crate) fn compute_powers_serial<F: FftField>(size: usize, root: F) -> Vec<F> {
    let mut value = F::one();
    (0..size)
        .map(|_| {
            let old_value = value;
            value *= root;
            old_value
        })
        .collect()
}

pub(super) fn roots_of_unity<F: FftField>(root: F, size: usize) -> Vec<F> {
    // TODO: check if this method can replace parallel compute powers.
    let log_size = ark_std::log2(size);
    // early exit for short inputs
    if log_size <= LOG_ROOTS_OF_UNITY_PARALLEL_SIZE {
        compute_powers_serial(size / 2, root)
    } else {
        let mut temp = root;
        // w, w^2, w^4, w^8, ..., w^(2^(log_size - 1))
        let log_powers: Vec<F> = (0..(log_size - 1))
            .map(|_| {
                let old_value = temp;
                temp.square_in_place();
                old_value
            })
            .collect();

        // allocate the return array and start the recursion
        let mut powers = vec![F::zero(); 1 << (log_size - 1)];
        roots_of_unity_recursive(&mut powers, &log_powers);
        powers
    }
}

fn roots_of_unity_recursive<F: FftField>(out: &mut [F], log_powers: &[F]) {
    assert_eq!(out.len(), 1 << log_powers.len());
    // base case: just compute the powers sequentially,
    // g = log_powers[0], out = [1, g, g^2, ...]
    if log_powers.len() <= LOG_ROOTS_OF_UNITY_PARALLEL_SIZE as usize {
        out[0] = F::one();
        for idx in 1..out.len() {
            out[idx] = out[idx - 1] * log_powers[0];
        }
        return;
    }

    // recursive case:
    // 1. split log_powers in half
    let (lr_lo, lr_hi) = log_powers.split_at((1 + log_powers.len()) / 2);
    let mut scr_lo = vec![F::default(); 1 << lr_lo.len()];
    let mut scr_hi = vec![F::default(); 1 << lr_hi.len()];
    // 2. compute each half individually
    rayon::join(
        || roots_of_unity_recursive(&mut scr_lo, lr_lo),
        || roots_of_unity_recursive(&mut scr_hi, lr_hi),
    );
    // 3. recombine halves
    // At this point, out is a blank slice.
    out.par_chunks_mut(scr_lo.len()).zip(&scr_hi).for_each(|(out_chunk, scr_hi)| {
        for (out_elem, scr_lo) in out_chunk.iter_mut().zip(&scr_lo) {
            *out_elem = *scr_hi * scr_lo;
        }
    });
}

#[inline(always)]
fn butterfly_fn_io<F: FftField>(((lo, hi), root): ((&mut F, &mut F), &F)) {
    let neg = *lo - *hi;
    *lo += *hi;
    *hi = neg;
    *hi *= *root;
}

#[inline(always)]
fn butterfly_fn_oi<F: FftField>(((lo, hi), root): ((&mut F, &mut F), &F)) {
    *hi *= *root;
    let neg = *lo - *hi;
    *lo += *hi;
    *hi = neg;
}

pub fn apply_butterfly_io<F: FftField>(
    xi: &mut [F],
    roots: &[F],
    step: usize,
    chunk_size: usize,
    num_chunks: usize,
    max_threads: usize,
    gap: usize,
) {
    xi.par_chunks_mut(chunk_size).for_each(|cxi| {
        let (lo, hi) = cxi.split_at_mut(gap);
        // If the chunk is sufficiently big that parallelism helps,
        // we parallelize the butterfly operation within the chunk.

        if gap > MIN_GAP_SIZE_FOR_PARALLELISATION && num_chunks < max_threads {
            lo.par_iter_mut().zip(hi).zip(roots.par_iter().step_by(step)).for_each(butterfly_fn_io);
        } else {
            lo.iter_mut().zip(hi).zip(roots.iter().step_by(step)).for_each(butterfly_fn_io);
        }
    });
}

pub fn apply_butterfly_oi<F: FftField>(
    xi: &mut [F],
    roots: &[F],
    step: usize,
    chunk_size: usize,
    num_chunks: usize,
    max_threads: usize,
    gap: usize,
) {
    xi.par_chunks_mut(chunk_size).for_each(|cxi| {
        let (lo, hi) = cxi.split_at_mut(gap);
        // If the chunk is sufficiently big that parallelism helps,
        // we parallelize the butterfly operation within the chunk.

        if gap > MIN_GAP_SIZE_FOR_PARALLELISATION && num_chunks < max_threads {
            lo.par_iter_mut().zip(hi).zip(roots.par_iter().step_by(step)).for_each(butterfly_fn_oi);
        } else {
            lo.iter_mut().zip(hi).zip(roots.iter().step_by(step)).for_each(butterfly_fn_oi);
        }
    });
}

pub fn io_helper<F: FftField>(xi: &mut [F], root: F) {
    let mut roots = roots_of_unity(root, xi.len());
    let mut step = 1;
    let mut first = true;

    let max_threads = rayon::current_num_threads();

    let mut gap = xi.len() / 2;
    while gap > 0 {
        // each butterfly cluster uses 2*gap positions
        let chunk_size = 2 * gap;
        let num_chunks = xi.len() / chunk_size;

        // Only compact roots to achieve cache locality/compactness if
        // the roots lookup is done a significant amount of times
        // Which also implies a large lookup stride.
        if num_chunks >= MIN_NUM_CHUNKS_FOR_COMPACTION {
            if !first {
                roots = roots.into_par_iter().step_by(step * 2).collect()
            }
            step = 1;
            roots.shrink_to_fit();
        } else {
            step = num_chunks;
        }
        first = false;

        apply_butterfly_io(xi, &roots[..], step, chunk_size, num_chunks, max_threads, gap);

        gap /= 2;
    }
}

pub fn oi_helper<F: FftField>(xi: &mut [F], root: F) {
    let roots_cache = roots_of_unity(root, xi.len());

    // The `cmp::min` is only necessary for the case where
    // `MIN_NUM_CHUNKS_FOR_COMPACTION = 1`. Else, notice that we compact
    // the roots cache by a stride of at least `MIN_NUM_CHUNKS_FOR_COMPACTION`.

    let compaction_max_size =
        core::cmp::min(roots_cache.len() / 2, roots_cache.len() / MIN_NUM_CHUNKS_FOR_COMPACTION);
    let mut compacted_roots = vec![F::default(); compaction_max_size];

    let max_threads = rayon::current_num_threads();

    let mut gap = 1;
    while gap < xi.len() {
        // each butterfly cluster uses 2*gap positions
        let chunk_size = 2 * gap;
        let num_chunks = xi.len() / chunk_size;

        // Only compact roots to achieve cache locality/compactness if
        // the roots lookup is done a significant amount of times
        // Which also implies a large lookup stride.
        let (roots, step) = if num_chunks >= MIN_NUM_CHUNKS_FOR_COMPACTION && gap < xi.len() / 2 {
            compacted_roots[..gap]
                .par_iter_mut()
                .zip(roots_cache[..(gap * num_chunks)].par_iter().step_by(num_chunks))
                .for_each(|(a, b)| *a = *b);
            (&compacted_roots[..gap], 1)
        } else {
            (&roots_cache[..], num_chunks)
        };

        apply_butterfly_oi(xi, roots, step, chunk_size, num_chunks, max_threads, gap);

        gap *= 2;
    }
}

/// The minimum number of chunks at which root compaction
/// is beneficial.
const MIN_NUM_CHUNKS_FOR_COMPACTION: usize = 1 << 7;

/// The minimum size of a chunk at which parallelization of `butterfly`s is beneficial.
/// This value was chosen empirically.
const MIN_GAP_SIZE_FOR_PARALLELISATION: usize = 1 << 10;

// minimum size at which to parallelize.
const LOG_ROOTS_OF_UNITY_PARALLEL_SIZE: u32 = 7;

#[cfg(test)]
mod tests {
    use std::{time::Instant, cmp, mem::size_of};

    use ark_bls12_381::Fr;
    use ark_ff::{UniformRand};
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain, UVPolynomial,
    };
    use rand::thread_rng;
    use rust_gpu_tools::Device;
    

    use super::*;
    use crate::gpu::{Domain, FFTDomain, KERNELS};

    #[test]
    fn test() {
        let rng = &mut thread_rng();

        let l = 8192;

        let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();

        let mut x = DensePolynomial::<Fr>::rand(domain.size() - 1, rng);
        let mut y = x.clone();

        domain.fft_in_place(&mut x.coeffs);

        fft_helper_in_place(&mut y, domain.group_gen);
        derange(&mut y, domain.log_size_of_group);

        assert_eq!(x, y);

        domain.ifft_in_place(&mut x.coeffs);

        derange(&mut y, domain.log_size_of_group);
        ifft_helper_in_place(&mut y, domain.group_gen_inv);

        assert_eq!(x, y);
    }

    // #[test]
    // fn test_fft() {
    //     let rng = &mut thread_rng();

    //     for l in 2..27 {
    //         let n = 1 << l;

    //         let domain = Domain::new(n);

    //         let mut x = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    //         let mut y = x.clone();

    //         let now = Instant::now();
    //         io_helper(&mut x, domain.generator());
    //         println!("{:?}", now.elapsed());

    //         let now = Instant::now();
    //         KERNELS[0].lock().unwrap().butterfly_io3(&mut y, domain.n.size, &domain.n.omegas);
    //         println!("{:?}", now.elapsed());

    //         assert_eq!(x, y);
    //     }

    //     let n = 1 << 27;

    //     let domain = Domain::new(n);

    //     let mut x = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    //     let mut y = x.clone();

    //     let now = Instant::now();
    //     fft_helper_in_place(&mut x, domain.generator());
    //     println!("{:?}", now.elapsed());

    //     // let now = Instant::now();
    //     // KERNELS[0].lock().unwrap().butterfly_io3(
    //     //     &mut z,
    //     //     &domain,
    //     //     1,
    //     //     0
    //     // );
    //     // println!("{:?}", now.elapsed());

    //     // let now = Instant::now();
    //     // KERNELS[0].lock().unwrap().fft_inner(
    //     //     &mut y,
    //     //     &domain.n.pq,
    //     //     &domain.n.omegas,
    //     //     domain.n.log_size,
    //     // );
    //     // println!("{:?}", now.elapsed());

    //     // assert_eq!(x, z);

    //     let m = 1 << 23;

    //     let now = Instant::now();
    //     let mut gap = n / 2;
    //     let mut num_chunks = 1;
    //     while gap > m {
    //         for i in (0..num_chunks * gap).step_by(m) {
    //             let offset = i % gap;
    //             let l_start = 2 * i - offset;
    //             let l_end = l_start + m;
    //             let r_start = l_start + gap;
    //             let r_end = r_start + m;
    //             KERNELS[0].lock().unwrap().butterfly_io2(
    //                 unsafe { &mut *(&y[l_start..l_end] as *const _ as *mut _) },
    //                 unsafe { &mut *(&y[r_start..r_end] as *const _ as *mut _) },
    //                 &domain.n.omegas,
    //                 num_chunks,
    //                 offset,
    //             );
    //         }
    //         gap /= 2;
    //         num_chunks *= 2;
    //     }
    //     for i in (0..n).step_by(2 * m) {
    //         KERNELS[0].lock().unwrap().butterfly_io3(
    //             &mut y[i..i + 2 * m],
    //             domain.n.size,
    //             &domain.n.omegas,
    //         );
    //     }
    //     println!("{:?}", now.elapsed());

    //     assert_eq!(x, y);
    // }

    // #[test]
    // fn test_inv() {
    //     let rng = &mut thread_rng();

    //     for l in 2..27 {
    //         let n = 1 << l;

    //         let domain = Domain::new(n);

    //         let mut x = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    //         let mut y = x.clone();

    //         let now = Instant::now();
    //         oi_helper(&mut x, domain.generator_inv());
    //         println!("{:?}", now.elapsed());

    //         let now = Instant::now();
    //         KERNELS[0].lock().unwrap().butterfly_oi3(&mut y, domain.n.size, &domain.n.omegas_inv);
    //         println!("{:?}", now.elapsed());

    //         assert_eq!(x, y);
    //     }

    //     let n = 1 << 27;

    //     let domain = Domain::new(n);

    //     let mut x = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    //     let mut y = x.clone();

    //     let now = Instant::now();
    //     oi_helper(&mut x, domain.generator_inv());
    //     println!("{:?}", now.elapsed());

    //     let m = 1 << 23;

    //     let now = Instant::now();
    //     for i in (0..n).step_by(2 * m) {
    //         KERNELS[0].lock().unwrap().butterfly_oi3(
    //             &mut y[i..i + 2 * m],
    //             domain.n.size,
    //             &domain.n.omegas_inv,
    //         );
    //     }
    //     let mut gap = m * 2;
    //     let mut num_chunks = n / 2 / gap;
    //     while gap < n {
    //         for i in (0..num_chunks * gap).step_by(m) {
    //             let offset = i % gap;
    //             let l_start = 2 * i - offset;
    //             let l_end = l_start + m;
    //             let r_start = l_start + gap;
    //             let r_end = r_start + m;
    //             KERNELS[0].lock().unwrap().butterfly_oi2(
    //                 unsafe { &mut *(&y[l_start..l_end] as *const _ as *mut _) },
    //                 unsafe { &mut *(&y[r_start..r_end] as *const _ as *mut _) },
    //                 &domain.n.omegas_inv,
    //                 num_chunks,
    //                 offset,
    //             );
    //         }
    //         gap *= 2;
    //         num_chunks /= 2;
    //     }
    //     println!("{:?}", now.elapsed());

    //     assert_eq!(x, y);
    // }

    #[test]
    fn find_bad_gpu() {
        let rng = &mut thread_rng();
        let mut max_size = usize::MAX;
        for device in Device::all().iter() {
            max_size = cmp::min(max_size, device.memory() as usize / 2 / size_of::<Fr>());
        }
        max_size = max_size.next_power_of_two();
        let domain = Domain::new(max_size);
        for (i, kernel) in KERNELS.iter().enumerate() {
            println!("Testing GPU {}", i);
            let mut x = (0..max_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let mut y = x.clone();
            kernel.lock().unwrap().butterfly_io3(&mut x, domain.size(), &domain.n.omegas);
            fft_helper_in_place(&mut y, domain.generator());
            if x != y {
                panic!("Inconsistent results");
            }
            println!("OK");
        }
    }

    #[test]
    fn how_frequently_gpu_3_fails() {
        let rng = &mut thread_rng();
        let mut max_size = usize::MAX;
        for device in Device::all().iter() {
            max_size = cmp::min(max_size, device.memory() as usize / 2 / size_of::<Fr>());
        }
        max_size = max_size.next_power_of_two();
        let domain = Domain::new(max_size);
        let x = (0..max_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let mut y = x.clone();
        fft_helper_in_place(&mut y, domain.generator());
        let mut j = 0;
        for i in 0..100 {
            println!("{} / {}", j, i);
            let mut x = x.clone();
            KERNELS[3].lock().unwrap().butterfly_io3(&mut x, domain.size(), &domain.n.omegas);
            if x != y {
                j += 1;
            }
        }
        println!("{} / {}", j, 100);
    }

    #[test]
    fn test_fft() {
        let rng = &mut thread_rng();

        for l in 29..30 {
            let n = 1 << l;

            let domain = Domain::new(n);

            let mut x = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let mut y = x.clone();

            let now = Instant::now();
            fft_helper_in_place(&mut x, domain.generator());
            println!("cpu fft: {:?}", now.elapsed());

            let now = Instant::now();
            domain.fft_io(&mut y);
            println!("gpu fft1: {:?}", now.elapsed());

            if x != y {
                panic!();
            }

            let now = Instant::now();
            ifft_helper_in_place(&mut x, domain.generator_inv());
            println!("cpu ifft: {:?}", now.elapsed());

            let now = Instant::now();
            domain.ifft_oi(&mut y);
            println!("gpu ifft1: {:?}", now.elapsed());

            if x != y {
                panic!();
            }
        }
    }
}
