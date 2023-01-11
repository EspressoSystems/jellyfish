#include "./mont_t.cuh"
#include "./jacobian_t.hpp"

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
__device__ uint bitreverse(uint n, uint bits) {
  uint r = 0;
  for(int i = 0; i < bits; i++) {
    r = (r << 1) | (n & 1);
    n >>= 1;
  }
  return r;
}

extern __shared__ unsigned char cuda_shared[];

#define Fr_LIMBS 8
#define Fr_LIMB_BITS 32

#define Fr_BITS (Fr_LIMBS * Fr_LIMB_BITS)

__device__ bool get_bit(const fr_t& l, uint i) {
  return (l[Fr_LIMBS - 1 - i / Fr_LIMB_BITS] >> (Fr_LIMB_BITS - 1 - (i % Fr_LIMB_BITS))) & 1;
}

__device__ uint get_bits(fr_t l, uint skip, uint window) {
  l.from();
  uint ret = 0;
  for(uint i = 0; i < window; i++) {
    ret <<= 1;
    ret |= get_bit(l, skip + i);
  }
  return ret;
}

extern "C" __global__ void multiexp(
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
  const uint gid = blockIdx.x * blockDim.x + threadIdx.x;
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

__device__ fr_t pow_lookup(fr_t *bases, uint exponent) {
  return bases[exponent & 65535] * bases[(exponent >> 16) + 65536];
}

extern "C" __global__ void butterfly_io_update(fr_t* x, fr_t* y, fr_t* omegas, uint num_chunks, uint offset)
{
  const uint i = blockIdx.x * blockDim.x + threadIdx.x;

  fr_t neg = x[i] - y[i];
  x[i] += y[i];
  y[i] = neg;
  y[i] *= pow_lookup(omegas, (i + offset) * num_chunks);
}

extern "C" __global__ void butterfly_oi_update(fr_t* x, fr_t* y, fr_t* omegas, uint num_chunks, uint offset)
{
  const uint i = blockIdx.x * blockDim.x + threadIdx.x;

  y[i] *= pow_lookup(omegas, (i + offset) * num_chunks);
  fr_t neg = x[i] - y[i];
  x[i] += y[i];
  y[i] = neg;
}

extern "C" __global__ void butterfly_io_finalize(fr_t* x, uint len, fr_t* omegas, uint gap)
{
  fr_t* u = (fr_t*)cuda_shared;

  uint num_chunks = len / (gap * 2);
  uint a = gap / blockDim.x;
  const uint id = blockIdx.x / a * gap * 2 + (blockIdx.x & (a - 1)) + threadIdx.x * a;

  uint gap_u = blockDim.x;

  u[threadIdx.x] = x[id];
  u[threadIdx.x + gap_u] = x[id + gap];

  __syncthreads();

  for (uint t = 1; t <= blockDim.x; t *= 2) {
    const uint j = threadIdx.x & (gap_u - 1);
    const uint i = threadIdx.x * 2 - j;

    fr_t neg = u[i] - u[i + gap_u];
    u[i] += u[i + gap_u];
    u[i + gap_u] = neg * pow_lookup(omegas, ((id & ((gap / t) - 1))) * num_chunks);

    __syncthreads();

    gap_u /= 2;
    num_chunks *= 2;
  }

  x[id] = u[threadIdx.x];
  x[id + gap] = u[threadIdx.x + blockDim.x];
}

extern "C" __global__ void butterfly_oi_finalize(fr_t* x, uint len, fr_t* omegas, uint gap)
{
  fr_t* u = (fr_t*)cuda_shared;

  uint num_chunks = len / (gap * 2);
  const uint id = blockIdx.x / gap * gap * blockDim.x * 2 + (blockIdx.x & (gap - 1)) + threadIdx.x * gap * 2;

  uint gap_u = 1;

  u[threadIdx.x * 2] = x[id];
  u[threadIdx.x * 2 + gap_u] = x[id + gap];

  __syncthreads();

  for (uint t = 1; t <= blockDim.x; t *= 2) {
    const uint j = threadIdx.x & (gap_u - 1);
    const uint i = threadIdx.x * 2 - j;

    u[i + gap_u] *= pow_lookup(omegas, (((id - j * gap) & ((gap * t) - 1))) * num_chunks);
    fr_t neg = u[i] - u[i + gap_u];
    u[i] += u[i + gap_u];
    u[i + gap_u] = neg;

    __syncthreads();

    gap_u *= 2;
    num_chunks /= 2;
  }

  x[id] = u[threadIdx.x * 2];
  x[id + gap] = u[threadIdx.x * 2 + 1];
}
