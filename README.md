# Jellyfish cryptographic library (for ZPrize mid-term submission)

There are two verisons of our implementation: the GPU-only one, and the GPU + Distributed one.

The distributed version is currently not included in this repository, since the mid-term challenge is executed on a single server. Although spawning multiple nodes on one instance is possible and is allowed by our distributed implementation, it brings unnecessary communication and memory costs, and may exceed the RAM limitation of the server.

Please follow the instruction below to benchmark our GPU-only implementation:

1. Clone the repository
2. `cd ./zprice/`
3. Generate parameters: `cargo run --release --bin gen-param` (Or directly put the pregenerated `.bin` files in `data/`)
4. Run the benchmark: `cargo bench`

On our machine (i9-12900k, 32GB RAM + 8GB swap), the proof generation of our GPU-only implementation takes ~120s and 16GB RAM with `TREE_HEIGHT = 32` and `NUM_MEMBERSHIP_PROOFS = 640`, while the baseline takes ~230s and 40GB RAM.

## Overview of our optimization

We focus on optimizing the memory consumption during proof generation in order to align with the spec of provided servers.

We observe that in round 3, when computing the quotient polynomial, the baseline implementation runs `coset_fft` on `quot_domain` for `selectors`, `sigmas`, etc. *at the same time* to obtain the evaluations of `quot_poly`, so that the coefficients of `quot_poly` can be generated using only one IFFT. Although this approach is computationally efficient, the resulting vectors could be really large and are very likely to cause an OOM, because `quot_domain` is (about) 5x larger than `domain`.

On the other hand, our implementation do not generate the quotient polynomial in a single IFFT. Instead, we compute each parts of the polynomial separately and sequentially, so some intermediate evaluation vectors can be freed once they are no longer used.
