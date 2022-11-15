#include "./mont_t.cuh"
#include "./jacobian_t.hpp"

#define DEVICE __device__
#define GLOBAL
#define KERNEL extern "C" __global__
#define LOCAL __shared__

#define GET_GLOBAL_ID() blockIdx.x * blockDim.x + threadIdx.x
#define GET_GROUP_ID() blockIdx.x
#define GET_LOCAL_ID() threadIdx.x
#define GET_LOCAL_SIZE() blockDim.x
#define BARRIER_LOCAL() __syncthreads()

typedef unsigned char uchar;

#define TO_CUDA_T(limb64) (uint32_t)(limb64), (uint32_t)(limb64 >> 32)
static __device__ __constant__ const uint32_t BLS12_381_P[12] = {
    TO_CUDA_T(0xb9feffffffffaaab), TO_CUDA_T(0x1eabfffeb153ffff),
    TO_CUDA_T(0x6730d2a0f6b0f624), TO_CUDA_T(0x64774b84f38512bf),
    TO_CUDA_T(0x4b1ba7b6434bacd7), TO_CUDA_T(0x1a0111ea397fe69a)};
static __device__ __constant__ const uint32_t BLS12_381_RR[12] = {/* (1<<768)%P */
                                                                  TO_CUDA_T(0xf4df1f341c341746), TO_CUDA_T(0x0a76e6a609d104f1),
                                                                  TO_CUDA_T(0x8de5476c4c95b6d5), TO_CUDA_T(0x67eb88a9939d83c0),
                                                                  TO_CUDA_T(0x9a793e85b519952d), TO_CUDA_T(0x11988fe592cae3aa)};
static __device__ __constant__ const uint32_t BLS12_381_one[12] = {/* (1<<384)%P */
                                                                   TO_CUDA_T(0x760900000002fffd), TO_CUDA_T(0xebf4000bc40c0002),
                                                                   TO_CUDA_T(0x5f48985753c758ba), TO_CUDA_T(0x77ce585370525745),
                                                                   TO_CUDA_T(0x5c071a97a256ec6d), TO_CUDA_T(0x15f65ec3fa80e493)};
static __device__ __constant__ const uint32_t BLS12_381_M0 = 0xfffcfffd;

static __device__ __constant__ const uint32_t BLS12_381_r[8] = {
    TO_CUDA_T(0xffffffff00000001), TO_CUDA_T(0x53bda402fffe5bfe),
    TO_CUDA_T(0x3339d80809a1d805), TO_CUDA_T(0x73eda753299d7d48)};
static __device__ __constant__ const uint32_t BLS12_381_rRR[8] = {/* (1<<512)%P */
                                                                  TO_CUDA_T(0xc999e990f3f29c6d), TO_CUDA_T(0x2b6cedcb87925c23),
                                                                  TO_CUDA_T(0x05d314967254398f), TO_CUDA_T(0x0748d9d99f59ff11)};
static __device__ __constant__ const uint32_t BLS12_381_rone[8] = {/* (1<<256)%P */
                                                                   TO_CUDA_T(0x00000001fffffffe), TO_CUDA_T(0x5884b7fa00034802),
                                                                   TO_CUDA_T(0x998c4fefecbc4ff5), TO_CUDA_T(0x1824b159acc5056f)};
static __device__ __constant__ /*const*/ uint32_t BLS12_381_m0 = 0xffffffff;
typedef mont_t<381, BLS12_381_P, BLS12_381_M0,
                    BLS12_381_RR, BLS12_381_one> fp_t;
typedef mont_t<255, BLS12_381_r, BLS12_381_m0,
                    BLS12_381_rRR, BLS12_381_rone> fr_t;
typedef jacobian_t<fp_t> point_t;
typedef point_t::affine_t affine_t;

// Reverse the given bits. It's used by the FFT kernel.
DEVICE uint bitreverse(uint n, uint bits) {
  uint r = 0;
  for(int i = 0; i < bits; i++) {
    r = (r << 1) | (n & 1);
    n >>= 1;
  }
  return r;
}

extern LOCAL uchar cuda_shared[];

#define Fr_LIMBS 8
#define Fr_LIMB_BITS 32

#define Fr_BITS (Fr_LIMBS * Fr_LIMB_BITS)

DEVICE bool get_bit(fr_t l, uint i) {
  return (l[Fr_LIMBS - 1 - i / Fr_LIMB_BITS] >> (Fr_LIMB_BITS - 1 - (i % Fr_LIMB_BITS))) & 1;
}

DEVICE uint get_bits(fr_t l, uint skip, uint window) {
  uint ret = 0;
  for(uint i = 0; i < window; i++) {
    ret <<= 1;
    ret |= get_bit(l, skip + i);
  }
  return ret;
}

KERNEL void multiexp(
    const affine_t *bases,
    point_t *buckets,
    point_t *results,
    const fr_t *exps,
    uint n,
    uint num_groups,
    uint num_windows,
    uint window_size)
{
  // We have `num_windows` * `num_groups` threads per multiexp.
  const uint gid = GET_GLOBAL_ID();
  if(gid >= num_windows * num_groups) return;

  // We have (2^window_size - 1) buckets.
  const uint bucket_len = ((1 << window_size) - 1);

  // Each thread has its own set of buckets in global memory.
  buckets += bucket_len * gid;

  for(uint i = 0; i < bucket_len; i++) buckets[i].inf();

  const uint len = (uint)ceil(n / (float)num_groups); // Num of elements in each group

  // This thread runs the multiexp algorithm on elements from `nstart` to `nened`
  // on the window [`bits`, `bits` + `w`)
  const uint nstart = len * (gid / num_windows);
  const uint nend = min(nstart + len, n);
  const uint bits = (gid % num_windows) * window_size;
  const ushort w = min((ushort)window_size, (ushort)(Fr_BITS - bits));

  point_t res;
  res.inf();
  for(uint i = nstart; i < nend; i++) {
    uint ind = get_bits(exps[i], bits, w);
    if(ind--) buckets[ind].add(bases[i]);
  }

  // Summation by parts
  // e.g. 3a + 2b + 1c = a +
  //                    (a) + b +
  //                    ((a) + b) + c
  point_t acc;
  acc.inf();
  for(int j = bucket_len - 1; j >= 0; j--) {
    acc.add(buckets[j]);
    res.add(acc);
  }

  results[gid] = res;
}

DEVICE fr_t pow_lookup(GLOBAL fr_t *bases, uint exponent) {
  fr_t res = fr_t::one();
  uint i = 0;
  while(exponent > 0) {
    if (exponent & 1)
      res = res * bases[i];
    exponent = exponent >> 1;
    i++;
  }
  return res;
}

DEVICE fr_t pow(fr_t base, uint exponent) {
  fr_t res = fr_t::one();
  while(exponent > 0) {
    if (exponent & 1)
      res *= base;
    exponent = exponent >> 1;
    base.sqr();
  }
  return res;
}

KERNEL void radix_fft(GLOBAL fr_t* x, // Source buffer
                      GLOBAL fr_t* y, // Destination buffer
                      GLOBAL fr_t* pq, // Precalculated twiddle factors
                      GLOBAL fr_t* omegas, // [omega, omega^2, omega^4, ...]
                      LOCAL fr_t* u_arg, // Local buffer to store intermediary values
                      uint n, // Number of elements
                      uint lgp, // Log2 of `p` (Read more in the link above)
                      uint deg, // 1=>radix2, 2=>radix4, 3=>radix8, ...
                      uint max_deg) // Maximum degree supported, according to `pq` and `omegas`
{
// CUDA doesn't support local buffers ("shared memory" in CUDA lingo) as function arguments,
// ignore that argument and use the globally defined extern memory instead.
  // There can only be a single dynamic shared memory item, hence cast it to the type we need.
  fr_t* u = (fr_t*)cuda_shared;

  uint lid = GET_LOCAL_ID();
  uint lsize = GET_LOCAL_SIZE();
  uint index = GET_GROUP_ID();
  uint t = n >> deg;
  uint p = 1 << lgp;
  uint k = index & (p - 1);

  x += index;
  y += ((index - k) << deg) + k;

  uint count = 1 << deg; // 2^deg
  uint counth = count >> 1; // Half of count

  uint counts = count / lsize * lid;
  uint counte = counts + count / lsize;

  // Compute powers of twiddle
  const fr_t twiddle = pow_lookup(omegas, (n >> lgp >> deg) * k);
  fr_t tmp = pow(twiddle, counts);
  for(uint i = counts; i < counte; i++) {
    u[i] = tmp * x[i*t];
    tmp = tmp * twiddle;
  }
  BARRIER_LOCAL();

  const uint pqshift = max_deg - deg;
  for(uint rnd = 0; rnd < deg; rnd++) {
    const uint bit = counth >> rnd;
    for(uint i = counts >> 1; i < counte >> 1; i++) {
      const uint di = i & (bit - 1);
      const uint i0 = (i << 1) - di;
      const uint i1 = i0 + bit;
      tmp = u[i0];
      u[i0] = u[i0] + u[i1];
      u[i1] = tmp - u[i1];
      if(di != 0) u[i1] = pq[di << rnd << pqshift] * u[i1];
    }

    BARRIER_LOCAL();
  }

  for(uint i = counts >> 1; i < counte >> 1; i++) {
    y[i*p] = u[bitreverse(i, deg)];
    y[(i+counth)*p] = u[bitreverse(i + counth, deg)];
  }
}
