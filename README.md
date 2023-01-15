# Jellyfish cryptographic library (for ZPrize final submission)

## Notations

* $ck$: commitment key
* $k_i$: $i$-th cosset representative
* $w_i$ / $W_i$: $i$-th wire polynomial / evaluations, where $i \in [0, 4]$
* $q_{a_i}$ / $Q_{a_i}$: $i$-th linear combination selector polynomial / evaluations, where $i \in [0, 3]$
* $q_{h_i}$ / $Q_{h_i}$: $i$-th hash selector polynomial / evaluations, where $i \in [0, 3]$
* $q_{m_i}$ / $Q_{m_i}$: $i$-th multiplication selector polynomial / evaluations, where $i \in [0, 1]$
* $q_e$ / $Q_e$: elliptic curve selector polynomial / evaluations
* $q_c$ / $Q_c$: constant selector polynomial / evaluations
* $q_o$ / $Q_o$: output selector polynomial / evaluations
* $\sigma_i$ / $\Sigma_i$: $i$-th wire permutation polynomial / evaluations, where $i \in [0, 4]$
* $p$ / $P$: public input polynomial / evaluations 
* $z$ / $Z$: permutation polynomial / evaluations
* $t / T$: quotient polynomial / evaluations
    * $t_i$: $i$-th part of quotient polynomial, where $i \in [0, 4]$
* $r / R$: opening polynomial / evaluations

## Overview

### What to distribute?

For Groth16, DIZK distributes algorithms like MSM or FFT. We initially followed the same approach for (Turbo)-PLONK, but found that network communication was way too costly, especially for the FFT operations when computing the quotient polynomial $t$.

Take a circuit with 2^28 constraints as an example, a single wire polynomial takes 8 GB of memory, and its evaluations in the quotient domain takes 64 GB. DIZK's approach requires the 64 GB of data to be sent over the network about 3 times (map + shuffle + reduce), and there are 18 different polynomials (5 wires, 13 selectors), which require 64 * 3 * 18 = 3.456 TB of network traffic and take about 1 hour to transfer with bandwidth 1 GB(yte)/s.

We aim to reduce the communication cost and avoid sending polynomials over the network when possible. In our current architecture, what we distribute are more coarse-grained workloads.

For instance, in round 3, one part of quotient polynomial $t$ is $q_{a_0} w_0 + q_{h_0} w_0^4 + q_{a_1} w_1 + q_{h_1} w_1^4 + q_{a_2} w_2 + q_{h_2} w_2^4 + q_{a_3} w_3 + q_{h_3} w_3^4$, which can be computed by 4 workers independently (assume that they already know their own $q_{a_i}$, $q_{h_i}$ and $w_i$). The only network communication occurs when computing the sum of the 4 results.

This intuition leads to the following workflow.

### Workflow

![Workflow](./assets/workflow.svg)

> The actual code is slightly different from the diagram above, because we have to take memory into account.

### Interoperate with GPUs

As illustrated in the workflow diagram, what we distribute is the proving key and the wires, while the operations on these polynomials are done separately by each worker. The operations majorly include MSM and FFT, which are accelerated using GPUs.

Pippenger's algorithm is used for MSM, which is parallelizable and can be distributed across multiple GPUs.

Parallelizing FFT is not that easy, especially when the polynomial cannot fit into the memory of a single GPU. We tried both DIZK's approach and the well-known Cooley-Tukey algorithm, and found that the latter is much faster.
* DIZK's approach:
    1. A degree $n - 1$ polynomial is considered as a matrix of size $\sqrt{n} \times \sqrt{n}$. CPU transposes the matrix in-place in memory.
    2. The FFT in a domain with size $n$ is split into $\sqrt{n}$ FFTs in a domain with size $\sqrt{n}$. Run the smaller FFTs concurrently on multiple GPUs. Each GPU handles a batch of smaller FFTs, where the batch size $b$ is determined by the memory size of the GPU. For $m$ GPUs, such a process is repeated $\frac{\sqrt{n}}{mb}$ times.
    3. Repeat step 1 again.
    4. Repeat step 2 again.
    5. Repeat step 1 again.
* Cooley-Tukey:
    1. When the butterfly size is larger than the GPU memory size, split the butterfly into chunks. Collect the chunks of all the butterflies in the current round, and distribute them evenly to the GPUs. Each GPU sequentially processes the chunks of butterflies assigned to it, but in parallel with other GPUs.
    2. Repeat step 1 until the butterfly size is smaller than the GPU memory size.
    3. Now a GPU can process the butterfly (and all the butterflies in the following rounds) on its own. Run the remaining rounds in parallel on multiple GPUs.

For the reason why Cooley-Tukey is faster, we believe it is because DIZK's approach requires 3 transpositions. The transposition is done in-place on CPU due to the limited memory size, which is slower than out-of-place algorithms.

### Trade-off between memory and performance

It is very unlikely that the memory size of a worker can hold all the polynomials and intermediate values. We have to save memory by storing some of the data on disk, without sacrificing the performance too much.

Our approach is based on the following observations:

* Memory access is faster than disk IO.
* Disk read is faster than disk write.

Therefore, we try to minimize the number of disk writes and work in memory as much as possible.

1. In `KeyGen`, $ck$ is stored on disk once received, and is mmaped to memory when committing to polynomials. The (partial) proving key $q_{\star}$ and $\sigma_i$ and evaluations $W_i$ and $\Sigma_i$ are generated in memory and written to disk in the end.
2. In Round 1 of `Prove`, $W_i$ is read from disk and stored in memory. IFFT is done in-place on $W_i$.
3. In Round 2 of `Prove`, $W_i$ is read from disk and stored in memory, and $\Sigma_i$ is mmaped to memory. $Z_i$ is temporarily stored in memory, and is freed after worker 4 finishes the computation. Worker 4 keeps $z$ in memory.
4. In Round 3 of `Prove`, when computing the multiplication of $m$ polynomials, the first polynomial is read from disk (or copied from existing memory space) and stored in memory, and the result of FFT is saved back to disk. The same process is repeated $m - 1$ times. For the last polynomial, the result of FFT is directly stored in memory, and is updated in-place by multiplying the mmapped evaluations of the other polynomials. Finally, we compute the IFFT of the result, split it into chunks, and send the chunks to the corresponding workers. $i$-th worker stores $t_{4 - i}$ in memory, and updates it when receiving chunks from peers.
5. In Round 4 of `Prove`, $w_i$ and $\sigma_i$ are mmaped to memory ($z$ is already in the memory of worker 4) to compute the evaluation at $\zeta$.
6. In Round 5 of `Prove`, $t_i$ is updated in-place by adding the mmaps of $w_i$, $\sigma_i$ and $q_{\star}$. Worker 4 receives the final $t_i$'s from peers, calculates the sum of them, computes and commits to the opening polynomial in memory. $t_i$'s can be freed now. Worker 4 also computes the shifted opening polynomial and its commitment in memory based on $z$. $z$ can be freed now.

All the mmaps above are immutable. Although we can create mutable mmaps and operate directly on them, our experiments show that it is slower than copying the data to memory and operating on the copy when the program frequently mutates the data, e.g., when computing FFT and IFFT.

## Implementation Details

> The requirement of ZPrize is just to distribute the proof generation process, but we also improve other parts of PLONK to make the development experience less painful.

### Universal Setup

This is done by a single party. `fixed_msm` is refactored to remove some intermediate allocations.

### Circuit Generation

This is done individually by the dispatcher and all the workers. We refactor the code for circuit generation, and make it faster and more memory efficient.

* Speed: the test circuit ensures the validity of `NUM_MEMBERSHIP_PROOFS` membership proofs. Because each membership proof can be validated independently, circuit generation can be efficiently parallelized:
    1. Generate small circuits for each membership proof in parallel.
    2. Adjust the index of witnesses and gates.
    3. Merge the circuits into a large one.

* Memory: the struct `PlonkCircuit` consists of the following fields, where `Variable`, `GateId` and `WireId` are type aliases of `usize`:
    ```rs
    pub struct PlonkCircuit<F> where F: FftField {
        num_vars: usize,
        gates: Vec<Box<dyn Gate<F>>>,
        wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
        pub_input_gate_ids: Vec<GateId>,
        witness: Vec<F>,
        wire_permutation: Vec<(WireId, GateId)>,
        extended_id_permutation: Vec<F>,
        num_wire_types: usize,
        eval_domain: Radix2EvaluationDomain<F>,
    }
    ```

    Among them, `wire_permutation` and `extended_id_permutation` are only required in key generation and round 2 of proof generation, and as shown in the workflow diagram, round 2 can be done even without them. Therefore, we remove them from `PlonkCircuit` and generate them on the fly when needed.

    Also, `gates` is a vector of pointers to gates that implement trait `Gate`, which may take up to 5 field elements (160 bytes), e.g., `RescueAffineGate` and `Power5NonLinearGate`. Note that `RescueAffineGate` and `Power5NonLinearGate` just records the `i`-th round constant in the `r`-th round and the `i`-th vector of MDS matrix. Since round constants and MDS matrix are fixed, we can let `RescueAffineGate` and `Power5NonLinearGate` hold the index `i` and round number `r`, and get the actual selectors from a global table. Furthermore, because $i \in [0, 3], r \in [0, 24]$, we can use `u8` to represent them, and in total each of them just cost 2 bytes, which is 80x smaller than the original gates (This can be further optimized by encoding `i` in 2 bits, and `r` in 5 bits, resulting in 1 byte per gate). 
    
    In addition, if our understanding is correct, `Box<dyn T>` is a fat pointer which takes 16 bytes, and we believe there are more space-saving ways to represent gates. We converted each gate from a trait object to a struct holding the following enum, which takes only 3 bytes:

    ```rs
    pub enum GateType {
        Padding,
        Zero,
        One,
        Addition,
        Equality,
        Multiplication,
        Bool,
        Io,
        FifthRoot,
        CondSelect,
        RescueAddConstant(u8),
        RescueAffine(u8, u8),
        Power5NonLinear(u8, u8),
        MidNode,
    }
    ```

    > We "cheat" in our implementation - only gates related to the membership proof are implemented. However, it should be trivial to extend our code and support other gates like `EdwardsCurveEquationGate`, etc.

### Proving/Verification Key Generation

This is done by the workers. Each worker will get a copy of $ck$ from the dispatcher. Then, a seed for circuit generation is chosen by the dispatcher and is sent to all the workers, so that they can generate the same circuit.

Each worker computes and stores a part of the proving key from the circuit, and returns the corresponding part of the verification key to the dispatcher. Specifically,
* Type 1 worker (worker 0 and worker 2) stores $q_{a_i}, q_{h_i}, \sigma_i, \Sigma_i$ and $W_i$,
* Type 2 worker (worker 1 and worker 3) stores $q_{a_i}, q_{h_i}, q_{m_{(i - 1) / 2}}, \sigma_i, \Sigma_i$ and $W_i$,
* and Type 3 worker (worker 4) stores $q_e, q_c, q_o, \sigma_i, \Sigma_i, W_i$. In addition, public input polynomial is also managed by Type 3 worker.

The dispatcher merges all the selector commitments and the sigma commitments to construct the final $vk$. $vk$ and $P$ are appended to the transcript.

### Proof Generation

#### Round 1

Each worker computes its own $w_i$ and generate a commitment $c_{w_i}$. The dispatcher collects $\{ c_{w_i} \}$ and appends them to the transcript.

#### Round 2

The dispatcher gets $\beta$ and $\gamma$ from RO, and sends them to each worker.

Each worker computes a component $Z_i$ of the evaluations $Z$, where the $k$-th value of $Z_i$ is $\prod_{j = 1}^k \frac{(W_i[j] + \beta k_i \omega^j + \gamma)}{(W_i[j] + \beta \Sigma_i[j] + \gamma)}$.

Worker 4 multiplies them together to get the perm polynomial $z$, and sends the commitment $c_z$ to the dispatcher. The dispatcher appends $c_z$ to the transcript.

#### Round 3

The dispatcher gets $\alpha$ from RO.

The $(4 - i)$-th worker maintains a temporary polynomial $t_i$, which is updated when receiving $t$'s parts from other workers. The final $t_i$ will be the $(n + 2) i$-th to $(n + 2) (i + 1)$-th coefficients of the quotient polynomial $t$.

First, each worker computes part I.I of the quotient polynomial. Specifically,
* Type 1 and Type 2 worker computes $\frac{q_{a_i} w_i + q_{h_i} w_i^5}{x^n - 1}$.
* Type 3 worker computes $\frac{q_c - q_o w_i + p}{x^n - 1}$.

> Doing the division ahead can decrease the degree of the polynomial and save the cost of communication. However, the denominator $x^n - 1$ may not divide the numerator. In fact, we add the remainder to the quotient when doing the division (for simplicity, we still use the notation $\frac{a}{b}$ to denote the quotient), by observing that the final numerator of $t$ is divisible by $x^n - 1$. This will produce the same $t$ as if we do the division after the numerator is fully computed.

The result is split into 5 chunks, and each chunk is sent to the corresponding worker.

Also, worker 4 receives $\alpha$ from the dispatcher, computes part IV of the quotient polynomial $\frac{\alpha^2}{n} \frac{z - 1}{x - 1}$, and sends the result to itself (because its degree does not exceed $n + 2$).

Then,
* Type 1 worker $i$ sends $w_i$ to Type 2 worker $i + 1$, who computes $w_i w_{i + 1}$ and $(w_i \beta k_i x + \gamma)(w_{i + 1} \beta k_{i + 1} x + \gamma)$.
* Type 2 worker computes part I.II of the quotient polynomial $\frac{q_{m_{(i - 1) / 2}} w_{i} w_{i + 1}}{x^n - 1}$, and sends the $i$-th chunk of the result to $(4 - i)$-th worker.
* Type 3 worker gets $w_0 w_1$, $w_2 w_3$, $(w_0 \beta k_0 x + \gamma)(w_1 \beta k_1 x + \gamma) - w_0 w_1$, and $(w_2 \beta k_2 x + \gamma)(w_3 \beta k_3 x + \gamma) - w_2 w_3$ from Type 2 workers. It computes the sum of part I.III and part II of the quotient polynomial $\frac{q_e \prod w_i + \alpha z \prod (w_i \beta k_i x + \gamma)}{x^n - 1}$, and sends the $i$-th chunk of the result to $(4 - i)$-th worker.

> Type 3 worker gets the difference $(w_i \beta k_i x + \gamma)(w_{i + 1} \beta k_{i + 1} x + \gamma) - w_i w_{i + 1}$ because its size is $n + 3$, which is smaller than $(w_i \beta k_i x + \gamma)(w_{i + 1} \beta k_{i + 1} x + \gamma)$'s size $2 n + 3$.

At the same time, the dispatcher gets $(w_i + \beta \sigma_i + \gamma)$ from $i$-th worker and $z$ from worker 4, computes part III of the quotient polynomial $\frac{-\alpha z' \prod(w_i + \beta \sigma_i + \gamma)}{x^n - 1}$, and sends the $i$-th chunk of the result to $(4 - i)$-th worker.

> Computing part I.III, part II and part III of the quotient polynomial are the heaviest parts of PLONK and require the largest amount of memory. 5 of the provided servers have 70 GB of memory, and the remaining 1 has 120 GB. When $n = 2^28$, each worker needs about 8 GB to store $t_i$, so there are only 62 GB left on 70 GB servers. But the quotient domain has $2^31$ elements, which takes 64 GB. Therefore, we have to assign Type 3 worker to the server with 120 GB of memory. Also, the dispather does not need to store $t_i$, so it can share responsibility for computing I.III, part II or part III with the Type 3 worker.

Now, each worker has the final $t_i$. They commit to their $t_i$'s and send the commitment $c_{t_i}$ to the dispatcher. The dispatcher appends $\{ c_{t_i} \}$ to the transcript.

#### Round 4

The dispatcher gets $\zeta$ from RO, and sends it to each worker.

Type 1 and Type 2 workers computes the evaluations of $w_i$ and $\sigma_i$ at $\zeta$, and Type 3 worker computes the evaluations of $w_i$ and $z$ at $\zeta$.

The dispatcher collects $\{ w_i(\zeta) \}$, $\{ \sigma_i(\zeta) \}_{i < 4}$ and $z(\zeta)$ from workers, and appends them to the transcript.

#### Round 5

The dispatcher gets $v$ from RO, and sends it to each worker.

The following polynomials are computed by wokers:
* Type 1 and Type 2 worker computes $w_i(\zeta) q_{a_i} + w_i(\zeta)^5 q_{h_i}$.
* Type 2 worker computes $w_{i - 1}(\zeta) w_i(\zeta) q_{m_{(i - 1) / 2}}$.
* Type 3 worker computes $\prod w_i(\zeta) q_e + q_{c} - w_4(\zeta) q_{o}$.
* Type 1 and Type 2 worker computes $v^{i + 1} w_i + v^{i + 6} \sigma_i$.
* Type 3 worker computes $v^{i + 1} w_i$.
* Each worker computes $(1 - \zeta^n)\zeta^{(4 - i)(n + 2)} t_{4 - i}$.
* Type 3 worker computes $(\alpha^2 \frac{\zeta^n - 1}{n(\zeta - 1)} + \alpha \prod (w_i(\zeta) + \beta \zeta + \gamma))z$.
* Type 3 worker computes $-\alpha \beta z(\zeta \omega) \prod_{i < 4} (w_i(\zeta) + \beta \sigma_i(\zeta) + \gamma)\sigma_4$.

Worker 4 sums up the polynomials above, computes the opening polynomial $r$ from the sum, and sends the commitment $c_r$ to the dispatcher. In addition, worker 4 computes the shifted opening polynomial $r'$ from $z$ and $\zeta$, and sends the commitment $c_{r'}$ to the dispatcher.
 
The dispatcher outputs all the commitments and evaluations as the proof.

## Performance

Our implementation no longer provides the same interface as the baseline, and the original benchmark code becomes incompatible.

Instead, please follow the instruction below to "benchmark" our implementation:

1. Clone the repository
2. Switch to the `zprize_submission` branch
3. `cd jellyfish/distributed/`
4. Edit TOML files in `config/` to match your environment
5. On each server that acts as the worker, run `cargo run --release --bin worker -- $i`, where `$i` is the index of the worker (starting from 0). Worker 4 should run on the 120 GB server.
6. Generate parameters: `cargo run --release --bin keygen_dispatcher`
7. Run the "benchmark": `cargo run --release --bin prove_dispatcher`
    * `prove_dispatcher` actually runs the proof generation process and verifies the proof for 10 times and reports the time taken for each run.

For `TREE_HEIGHT = 21` and `NUM_MEMBERSHIP_PROOFS = 65536` (about 2^28 constraints), the proof generation takes about 48 minutes on the provided servers.

The maximum memory consumption on the dispatcher and 4 workers is about 65-66 GB, and on the remaining worker, it takes about 120 GB.
