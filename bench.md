# Plonk proof generation/verification



## Desktop
- Processor: AMD 5900x 12 core 24 thread at 3.7 GHz
- Memory: 16 GB 2667 MHz DDR4
- OS: ubuntu 20.04
- rustc 1.56.1 (59eed8a2a 2021-11-01)
- `RAYON_NUM_THREADS=24 cargo bench`

### TurboPlonk
| | Proving | Verifying | Batch Verifying |
|:---|---:|---:|---:|
| | ns/constraints | single proof | 1k proofs |
| BLS12-381 |  29591 | 2.083 ms |  7.445 ms | 
| BN-254    |  23069 | 1.459 ms |  6.540 ms |
| BW6-761   | 120446 | 10.885 ms |  19.615 ms |


### UltraPlonk
| | Proving | Verifying | Batch Verifying |
|:---|---:|---:|---:|
| | ns/constraints | single proof | 1k proofs |
| BLS12-381 |  41747 |  2.314 ms |  8.381 ms | 
| BN-254    |  33701 | 1.459 ms | 7.430 ms |
| BW6-761   | 162476 | 9.413 ms | 21.505 ms |



## Laptop
- MacBoo Pro (16-inch, 2019)
- Processor: 2.3 GHz 8-Core Intel Core i9
- Memory: 16 GB 2667 MHz DDR4
- `RAYON_NUM_THREADS=N cargo bench`

### TurboPlonk
| | Proving | Verifying | Batch Verifying |
|:---|---:|---:|---:|
| | ns/constraints | single proof | 1k proofs |
| BLS12-381 |  59317 |  3.207 ms |  17.683 ms | 
| BN-254    |  44857 | 2.364 ms |  14.803 ms |
| BW6-761   | 271828 | 12.504 ms |  37.909 ms |


### UltraPlonk
| | Proving | Verifying | Batch Verifying |
|:---|---:|---:|---:|
| | ns/constraints | single proof | 1k proofs |
| BLS12-381 |  89593 |  3.549 ms |  20.784 ms | 
| BN-254    |  70383 | 2.390 ms | 17.173 ms |
| BW6-761   | 373141 | 13.656 ms | 44.023 ms |

