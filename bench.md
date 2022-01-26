#### Plonk proof generation/verification
The sample benchmark result is the output from the following cmd
```
RAYON_NUM_THREADS=24 cargo bench
```


##### Environment
- Processor: AMD 5900x 12 core 24 thread at 3.7 GHz
- Memory: 16 GB 2667 MHz DDR4
- OS: ubuntu 20.04
- rustc 1.56.1 (59eed8a2a 2021-11-01)

##### TurboPlonk
- BLS12-381
  - Proving time: 29591 ns/constraint
  - Verifying time: 2.083 ms
  - Batch verifying time for 1000 proofs: 7.445 ms
- BN-254
  - Proving time: 23069 ns/constraint
  - Verifying time: 1.459 ms
  - Batch verifying time for 1000 proofs: 6.540 ms
- BW6-761
  - Proving time: 120446 ns/constraint
  - Verifying time: 10.885 ms
  - Batch verifying time for 1000 proofs: 19.615 ms

##### UltraPlonk
- BLS12-381
  - Proving time: 41747 ns/constraint
  - Verifying time: 2.314 ms
  - Batch verifying time for 1000 proofs: 8.381 ms
- BN-254
  - Proving time: 33701 ns/constraint
  - Verifying time: 1.459 ms
  - Batch verifying time for 1000 proofs: 7.430 ms
- BW6-761
  - Proving time: 162476 ns/constraint
  - Verifying time: 9.413 ms
  - Batch verifying time for 1000 proofs: 21.505 ms