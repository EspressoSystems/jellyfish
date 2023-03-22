// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![deny(missing_docs)]
//! This module implements Rescue hash function over the following fields
//! - bls12_377 base field
//! - ed_on_bls12_377 base field
//! - ed_on_bls12_381 base field
//! - ed_on_bn254 base field
//!
//! It also has place holders for
//! - bls12_381 base field
//! - bn254 base field
//! - bw6_761 base field
//!
//! Those three place holders should never be used.

#![deny(warnings)]
pub mod errors;
mod rescue_constants;
pub mod sponge;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, Zero};
use ark_std::{vec, vec::Vec};

/// The state size of rescue hash.
pub const STATE_SIZE: usize = 4;
/// The rate of the sponge used in RescueCRHF.
pub const CRHF_RATE: usize = 3;

/// The # of rounds of rescue hash.
// In the paper, to derive ROUND:
//  sage: m = 4
//  sage: for N in range (13):
//  ....:     t = m*N*3+3+2
//  ....:     b = m*N + 3
//  ....:     sec = factorial(t)/factorial(b)/factorial(t-b)
//  ....:     print (N, RR(log(sec^2,2)))
//
// for alpha = 5, (i.e., BLS12-381 and BN254)
//      10 224.672644456021
//      11 246.589942930803
//      12 268.516687541633
// set ROUND = 12, we have 134 bits security
//
// for alpha = 11, (i.e. BLS12-377) we have l1 =
//      7 227.364142668101
//      8 258.421493926570
//      9 289.491120346551
//      10 320.571247089962
//      11 351.660410749737
//      12 382.757409540148
// The smallest possible round number will be max(10, l1), which
// means round = 10 gives 160 bits security
//
// There is also the script from
//  https://github.com/EspressoSystems/Marvellous
//
// For unknown reasons, for all alpha >=5, the ROUND number is taken as if alpha
// = 5. This parameter choice does not seem to be optimal
//
//  if (self.alpha == 3):
//      self.Nb = max(10, 2*ceil((1.0 * security_level + 2) / (4*m)))
//  elif (self.alpha == 5):
//      self.Nb = max(10, 2*ceil((1.0 * security_level + 3) / (5.5*m)))
//  else :
//      self.Nb = max(10, 2*ceil((1.0 * security_level + 3) / (5.5*m)))
//  # where m = 4
//
// For conservative purpose, we are setting ROUNDS = 12 for now.
// We may consider to use ROUNDS = 10 for BLS12-377 (alpha = 11) in futures.
pub const ROUNDS: usize = 12;

/// This trait defines constants that are used for rescue hash functions.
pub trait RescueParameter: PrimeField + Absorb {
    /// parameter A, a.k.a., alpha
    const A: u64;
    /// parameter A^-1
    const A_INV: &'static [u64];
    /// MDS matrix
    const MDS_LE: [[&'static [u8]; STATE_SIZE]; STATE_SIZE];
    /// Initial vector.
    const INIT_VEC_LE: [&'static [u8]; STATE_SIZE];
    /// Injected keys for each round.
    const KEY_INJECTION_LE: [[&'static [u8]; 4]; 2 * ROUNDS];
    /// Permutation keys.
    const PERMUTATION_ROUND_KEYS: [[&'static [u8]; 4]; 25];
}

#[derive(Clone, Debug, Eq, PartialEq, Copy, Default)]
/// Data type for rescue prp inputs, keys and internal data
pub struct RescueVector<F> {
    pub(crate) vec: [F; STATE_SIZE],
}

// Public functions
impl<F: PrimeField> RescueVector<F> {
    /// zero vector
    pub fn zero() -> RescueVector<F> {
        RescueVector {
            vec: [F::zero(); STATE_SIZE],
        }
    }

    /// Return vector of the field elements
    /// WARNING: may expose the internal state.
    pub fn elems(&self) -> Vec<F> {
        self.vec.to_vec()
    }

    /// Perform a linear transform of the vector.
    /// Function needs to be public for circuits generation..
    pub fn linear(&mut self, matrix: &RescueMatrix<F>, vector: &RescueVector<F>) {
        let mut aux = matrix.mul_vec(self);
        aux.add_assign(vector);
        *self = aux
    }
}

// Private functions
impl<F: PrimeField> RescueVector<F> {
    fn from_elems_le_bytes(e0: &[u8], e1: &[u8], e2: &[u8], e3: &[u8]) -> RescueVector<F> {
        RescueVector {
            vec: [
                F::from_le_bytes_mod_order(e0),
                F::from_le_bytes_mod_order(e1),
                F::from_le_bytes_mod_order(e2),
                F::from_le_bytes_mod_order(e3),
            ],
        }
    }

    fn pow(&mut self, exp: &[u64]) {
        self.vec.iter_mut().for_each(|elem| {
            *elem = elem.pow(exp);
        });
    }

    fn add_assign(&mut self, vector: &RescueVector<F>) {
        for (a, b) in self.vec.iter_mut().zip(vector.vec.iter()) {
            a.add_assign(b);
        }
    }

    fn add(&self, vector: &RescueVector<F>) -> RescueVector<F> {
        let mut aux = *self;
        aux.add_assign(vector);
        aux
    }

    fn add_assign_elems(&mut self, elems: &[F]) {
        self.vec
            .iter_mut()
            .zip(elems.iter())
            .for_each(|(a, b)| a.add_assign(b));
    }

    fn dot_product(&self, vector: &RescueVector<F>) -> F {
        let mut r = F::zero();
        for (a, b) in self.vec.iter().zip(vector.vec.iter()) {
            r.add_assign(&a.mul(b));
        }
        r
    }
}

impl<F: RescueParameter> RescueVector<F> {
    /// Helper function to compute f(M,x,c) = Mx^a + c.
    /// Function needs to be public for circuits generation..
    pub fn non_linear(&mut self, matrix: &RescueMatrix<F>, vector: &RescueVector<F>) {
        let mut self_aux = *self;
        self_aux.pow(&[F::A]);
        let mut aux = matrix.mul_vec(&self_aux);
        aux.add_assign(vector);
        *self = aux;
    }
}

impl<F: Copy> From<&[F]> for RescueVector<F> {
    fn from(field_elems: &[F]) -> RescueVector<F> {
        assert_eq!(field_elems.len(), STATE_SIZE);
        RescueVector {
            vec: [
                field_elems[0],
                field_elems[1],
                field_elems[2],
                field_elems[3],
            ],
        }
    }
}

impl<F: Copy> From<&[F; STATE_SIZE]> for RescueVector<F> {
    fn from(field_elems: &[F; STATE_SIZE]) -> RescueVector<F> {
        RescueVector { vec: *field_elems }
    }
}

/// A matrix that consists of `STATE_SIZE` number of rescue vectors.
#[derive(Debug, Clone)]
pub struct RescueMatrix<F> {
    matrix: [RescueVector<F>; STATE_SIZE],
}

impl<F: PrimeField> From<&[RescueVector<F>; STATE_SIZE]> for RescueMatrix<F> {
    fn from(vectors: &[RescueVector<F>; STATE_SIZE]) -> Self {
        Self { matrix: *vectors }
    }
}

impl<F: PrimeField> RescueMatrix<F> {
    fn mul_vec(&self, vector: &RescueVector<F>) -> RescueVector<F> {
        let mut result = [F::zero(); STATE_SIZE];
        self.matrix
            .iter()
            .enumerate()
            .for_each(|(i, row)| result[i] = row.dot_product(vector));
        RescueVector { vec: result }
    }

    /// Accessing the i-th vector of the matrix.    
    /// Function needs to be public for circuits generation..
    /// WARNING: may expose the internal state.
    pub fn vec(&self, i: usize) -> RescueVector<F> {
        self.matrix[i]
    }

    /// Check if the matrix is empty.
    pub fn is_empty(&self) -> bool {
        self.matrix.is_empty()
    }

    /// Return the number of columns of the matrix.
    pub fn len(&self) -> usize {
        self.matrix.len()
    }
}

// Rescue Pseudorandom Permutation (PRP) implementation for the BLS12_381 Scalar
// field with 4 elements as key and input size. From the PRP it derives 3 hash
// functions: 1. Sponge construction with arbitrary input and output length
// 2. Sponge construction with input length multiple of the RATE (3) (no padding
// needed) 3. 3 to 1 hashing (same construction as 1 and 2, but limiting the
// input to 3 and output to 1
//

#[derive(Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
/// Rescue pseudo-random permutation (PRP) instance
pub struct PRP<F> {
    mds: RescueMatrix<F>,      // rescue permutation MDS matrix
    init_vec: RescueVector<F>, // rescue permutation initial constants
    key_injection: Vec<RescueVector<F>>, /* rescue permutation key injection constants to compute
                                * round keys */
}

impl<F: RescueParameter> Default for PRP<F> {
    fn default() -> Self {
        let mut key_injection = Vec::with_capacity(2 * ROUNDS);
        for bytes in F::KEY_INJECTION_LE.iter() {
            key_injection.push(RescueVector::from_elems_le_bytes(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ));
        }
        PRP {
            mds: RescueMatrix::from(&[
                RescueVector::from_elems_le_bytes(
                    F::MDS_LE[0][0],
                    F::MDS_LE[0][1],
                    F::MDS_LE[0][2],
                    F::MDS_LE[0][3],
                ),
                RescueVector::from_elems_le_bytes(
                    F::MDS_LE[1][0],
                    F::MDS_LE[1][1],
                    F::MDS_LE[1][2],
                    F::MDS_LE[1][3],
                ),
                RescueVector::from_elems_le_bytes(
                    F::MDS_LE[2][0],
                    F::MDS_LE[2][1],
                    F::MDS_LE[2][2],
                    F::MDS_LE[2][3],
                ),
                RescueVector::from_elems_le_bytes(
                    F::MDS_LE[3][0],
                    F::MDS_LE[3][1],
                    F::MDS_LE[3][2],
                    F::MDS_LE[3][3],
                ),
            ]),
            init_vec: RescueVector::from_elems_le_bytes(
                F::INIT_VEC_LE[0],
                F::INIT_VEC_LE[1],
                F::INIT_VEC_LE[2],
                F::INIT_VEC_LE[3],
            ),
            key_injection,
        }
    }
}

impl<F: RescueParameter> PRP<F> {
    /// Rescue pseudorandom permutation for Bls12381 scalars vectors of size 4
    /// without key scheduled keys (scheduling occurs online)
    pub fn prp(&self, key: &RescueVector<F>, input: &RescueVector<F>) -> RescueVector<F> {
        let round_keys = self.key_schedule(key);
        self.prp_with_round_keys(round_keys.as_slice(), input)
    }

    /// Rescue pseudorandom permutation for Bls12381 scalars vectors of size 4
    /// using scheduled keys
    pub fn prp_with_round_keys(
        &self,
        round_keys: &[RescueVector<F>],
        input: &RescueVector<F>,
    ) -> RescueVector<F> {
        assert_eq!(round_keys.len(), 2 * ROUNDS + 1);
        let mut perm_state = input.add(&round_keys[0]);
        round_keys[1..].iter().enumerate().for_each(|(round, key)| {
            if (round % 2).is_zero() {
                perm_state.pow(F::A_INV);
            } else {
                perm_state.pow(&[F::A]);
            }
            perm_state.linear(&self.mds, key)
        });
        perm_state
    }

    /// Key scheduling for rescue based PRP for Bls12_381 scalars vector of size
    /// 4
    pub fn key_schedule(&self, key: &RescueVector<F>) -> Vec<RescueVector<F>> {
        let mut aux = key.add(&self.init_vec);
        let mut round_keys = vec![aux];
        (0..2 * ROUNDS).for_each(|i| {
            let exp = if (i % 2).is_zero() { F::A_INV } else { &[F::A] };
            aux.pow(exp);
            aux.linear(&self.mds, &self.key_injection[i]);
            round_keys.push(aux);
        });
        round_keys
    }

    /// Return a pointer to the mds matrix.
    /// Does not expose secret states.
    #[inline]
    pub fn mds_matrix_ref(&self) -> &RescueMatrix<F> {
        &self.mds
    }

    /// Return a pointer to the key injection vectors.
    /// Function needs to be public for circuits generation..
    /// WARNING!!! May expose secret state if keys are supposed to be secret.
    #[inline]
    pub fn key_injection_vec_ref(&self) -> &[RescueVector<F>] {
        &self.key_injection
    }

    /// Return a pointer to the initial vectors.
    /// Does not expose secret states.
    #[inline]
    pub fn init_vec_ref(&self) -> &RescueVector<F> {
        &self.init_vec
    }
}

/// Instance of a unkeyed cryptographic permutation to be used for instantiation
/// hashing, pseudo-random function, and other cryptographic primitives
#[derive(Debug, Clone)]
pub struct Permutation<F> {
    rescue_prp: PRP<F>,
    round_keys: Vec<RescueVector<F>>,
}

impl<F: RescueParameter> From<PRP<F>> for Permutation<F> {
    fn from(rescue: PRP<F>) -> Self {
        let mut keys: Vec<RescueVector<F>> = Vec::with_capacity(2 * ROUNDS + 1);
        for key in F::PERMUTATION_ROUND_KEYS.iter() {
            keys.push(RescueVector::from_elems_le_bytes(
                key[0], key[1], key[2], key[3],
            ))
        }
        Permutation {
            rescue_prp: rescue,
            round_keys: keys,
        }
    }
}

impl<F: RescueParameter> Default for Permutation<F> {
    fn default() -> Self {
        Permutation::from(PRP::default())
    }
}

impl<F: RescueParameter> Permutation<F> {
    /// Return a pointer to the round key.
    /// Does not expose secret states.
    #[inline]
    pub fn round_keys_ref(&self) -> &[RescueVector<F>] {
        self.round_keys.as_slice()
    }

    /// Return a pointer to the mds matrix.
    /// Does not expose secret states.
    #[inline]
    pub fn mds_matrix_ref(&self) -> &RescueMatrix<F> {
        self.rescue_prp.mds_matrix_ref()
    }
    /// Compute the permutation on RescueVector `input`
    pub fn eval(&self, input: &RescueVector<F>) -> RescueVector<F> {
        self.rescue_prp
            .prp_with_round_keys(self.round_keys.as_slice(), input)
    }
}

#[cfg(test)]
mod test_prp {
    use crate::rescue::{RescueVector, PRP};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as Fr377;
    use ark_ed_on_bls12_381::Fq as Fr381;
    use ark_ed_on_bn254::Fq as Fr254;

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // rescue761.Sponge([0,0,0,0], 4)
    const OUTPUT761: [[u8; 48]; 4] = [
        [
            0x37, 0xBE, 0x12, 0x7E, 0xDF, 0x9C, 0xBF, 0xCE, 0x78, 0xE1, 0x4F, 0xEB, 0x69, 0xAC,
            0x89, 0x53, 0xE7, 0xC4, 0x8D, 0x89, 0x90, 0x77, 0x64, 0x0D, 0xD0, 0x87, 0x42, 0xDD,
            0x1F, 0x98, 0x30, 0xC8, 0x0F, 0x12, 0x6D, 0x7A, 0x49, 0xD3, 0x22, 0x2E, 0x12, 0xBA,
            0x5B, 0x0E, 0x29, 0xB7, 0x2C, 0x01,
        ],
        [
            0x68, 0xFE, 0x2E, 0x95, 0x57, 0xDA, 0x2E, 0x36, 0xEC, 0xC1, 0xC5, 0x8A, 0x19, 0x50,
            0xD7, 0xBE, 0x11, 0x00, 0x3D, 0x5B, 0xAA, 0x8C, 0xF8, 0x45, 0x6F, 0xDC, 0xE4, 0x1F,
            0xF0, 0x35, 0xC7, 0x62, 0x6A, 0xC2, 0x33, 0xE7, 0x98, 0x9F, 0x26, 0x2A, 0x6E, 0x89,
            0xD5, 0x43, 0x21, 0xF8, 0x67, 0x01,
        ],
        [
            0x84, 0xB4, 0x93, 0x04, 0x3B, 0x23, 0x3A, 0x1B, 0x43, 0xC3, 0x61, 0x61, 0x1B, 0xA0,
            0x59, 0xFB, 0x2E, 0x88, 0x76, 0x62, 0x28, 0xBB, 0x32, 0x6F, 0x27, 0x1C, 0xA9, 0xCA,
            0x60, 0xC1, 0xE0, 0x7A, 0x7D, 0x37, 0x2F, 0x95, 0x75, 0xDD, 0x37, 0x2A, 0x70, 0xD1,
            0xE4, 0x55, 0xDB, 0x50, 0x2F, 0x00,
        ],
        [
            0x4E, 0x01, 0x9E, 0x8A, 0x7F, 0x6F, 0x3B, 0xDE, 0x7F, 0xF5, 0x58, 0x0B, 0x1A, 0x34,
            0x95, 0x8D, 0xBC, 0x94, 0x88, 0xD8, 0x5D, 0x25, 0x7A, 0xB0, 0xCC, 0x72, 0xFE, 0x36,
            0xC3, 0x13, 0xCB, 0x1B, 0x7A, 0x69, 0xCF, 0xCC, 0xAB, 0x2B, 0x55, 0x11, 0x1E, 0xC5,
            0x7C, 0xFC, 0x47, 0x7D, 0x9D, 0x01,
        ],
    ];

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // rescue381.Sponge([0,0,0,0], 4)
    const OUTPUT381: [[u8; 32]; 4] = [
        [
            0x12, 0x53, 0x24, 0x66, 0x84, 0xA2, 0x4D, 0x2B, 0xC7, 0x28, 0x3E, 0x0F, 0x80, 0xDF,
            0x1A, 0xC3, 0x5B, 0xA1, 0xA9, 0x5B, 0x46, 0x60, 0xBD, 0xED, 0xA6, 0xD1, 0x43, 0xB7,
            0x60, 0xCA, 0x59, 0x0D,
        ],
        [
            0x1B, 0xBE, 0xAB, 0x6C, 0xAB, 0x62, 0xB7, 0xAB, 0x19, 0xDF, 0xFF, 0x4D, 0x73, 0xB5,
            0x78, 0x30, 0x72, 0xC0, 0xC6, 0xDA, 0x1F, 0x10, 0xAD, 0xD1, 0x28, 0x65, 0xB4, 0x94,
            0x6F, 0xAC, 0xE5, 0x4B,
        ],
        [
            0x07, 0x86, 0xBD, 0x9A, 0xB3, 0x35, 0x96, 0x22, 0xF0, 0xE5, 0xEA, 0xCC, 0x9C, 0x79,
            0x89, 0x1F, 0x9D, 0x1D, 0x43, 0x44, 0xCC, 0xA9, 0x9A, 0xB0, 0x0E, 0xC0, 0x57, 0x6B,
            0x07, 0xF8, 0x53, 0x06,
        ],
        [
            0x9C, 0x23, 0x34, 0xB3, 0x0A, 0xCD, 0x94, 0x11, 0x49, 0xC0, 0x9D, 0x90, 0x7E, 0x7E,
            0xC8, 0x51, 0x42, 0xD3, 0xCD, 0x5D, 0x05, 0x13, 0x31, 0x66, 0x4D, 0x36, 0x98, 0xCE,
            0xAC, 0x44, 0x5C, 0x60,
        ],
    ];
    // this value is cross checked with sage script
    // rescue377.Sponge([0,0,0,0], 4)
    const OUTPUT377: [[u8; 32]; 4] = [
        [
            0x65, 0xF2, 0xF2, 0x74, 0x15, 0x7A, 0x5A, 0xB5, 0xE0, 0x86, 0x46, 0x9D, 0xAE, 0x27,
            0x29, 0xE0, 0x08, 0x39, 0x0D, 0xA6, 0x44, 0x5E, 0x20, 0x76, 0x23, 0x42, 0xDA, 0xF0,
            0x49, 0xA3, 0x51, 0x02,
        ],
        [
            0x67, 0xB5, 0x6A, 0xBA, 0x4B, 0xB8, 0x0F, 0xE2, 0xFC, 0x3D, 0x7E, 0xFC, 0x70, 0xCA,
            0x3D, 0x1D, 0xAC, 0xDD, 0xEA, 0x62, 0x81, 0xD7, 0x08, 0x0B, 0x38, 0x5F, 0x0A, 0x68,
            0xEC, 0xED, 0x53, 0x02,
        ],
        [
            0x10, 0xC5, 0xA0, 0xA1, 0x8E, 0x8D, 0xBC, 0xAD, 0x99, 0xC3, 0xB4, 0xE9, 0x22, 0xC9,
            0xB1, 0xCF, 0x35, 0x46, 0xE3, 0x52, 0x99, 0x5B, 0xBE, 0x6E, 0x08, 0xFF, 0x4B, 0x2F,
            0xCE, 0xF0, 0xCB, 0x0A,
        ],
        [
            0x33, 0xB0, 0xD0, 0x58, 0xE9, 0x25, 0x15, 0xB2, 0x8A, 0x9D, 0x16, 0x04, 0xEB, 0x26,
            0xC4, 0x0E, 0x3F, 0xBF, 0xCF, 0x49, 0x20, 0xA8, 0x89, 0xE2, 0x16, 0x2D, 0x76, 0x19,
            0xDF, 0x01, 0x02, 0x09,
        ],
    ];

    // this value is cross checked with sage script
    // rescue254.Sponge([0,0,0,0], 4)
    const OUTPUT254: [[u8; 32]; 4] = [
        [
            0xDD, 0xE7, 0x55, 0x8E, 0x14, 0xF9, 0x4C, 0xEE, 0x9F, 0xCC, 0xB2, 0x02, 0xFC, 0x0E,
            0x54, 0x21, 0xF2, 0xAA, 0xB8, 0x48, 0x05, 0xDB, 0x9B, 0x7A, 0xD2, 0x36, 0xA5, 0xF1,
            0x49, 0x77, 0xB4, 0x17,
        ],
        [
            0x43, 0x5F, 0x99, 0x3C, 0xB7, 0xB3, 0x84, 0x74, 0x4E, 0x80, 0x83, 0xFF, 0x73, 0x20,
            0x07, 0xD9, 0x7B, 0xEC, 0x4B, 0x90, 0x48, 0x1D, 0xFD, 0x72, 0x4C, 0xF0, 0xA5, 0x7C,
            0xDC, 0x68, 0xC0, 0x25,
        ],
        [
            0x2C, 0x7B, 0x21, 0x09, 0x9D, 0x10, 0xE9, 0x5C, 0x36, 0x3E, 0x6D, 0x20, 0x28, 0xBB,
            0xDB, 0x1E, 0xED, 0xF4, 0x22, 0x9B, 0x3A, 0xEE, 0x1E, 0x6F, 0x89, 0x13, 0x3D, 0x1E,
            0x4C, 0xA0, 0xA6, 0x23,
        ],
        [
            0x25, 0x9B, 0x47, 0xA2, 0x29, 0xFD, 0xC1, 0x08, 0xA9, 0xD1, 0x44, 0x71, 0x15, 0x8A,
            0x5A, 0x1A, 0x55, 0x5B, 0x88, 0xAE, 0xD6, 0xF6, 0x57, 0xD3, 0x33, 0x07, 0xE1, 0x5B,
            0x71, 0x5F, 0x12, 0x25,
        ],
    ];

    #[test]
    fn test_rescue_perm_on_0_vec() {
        test_rescue_perm_on_0_vec_254();
        test_rescue_perm_on_0_vec_377();
        test_rescue_perm_on_0_vec_381();
        test_rescue_perm_on_0_vec_761();
    }

    fn test_rescue_perm_on_0_vec_254() {
        let rescue = PRP::<Fr254>::default();
        let key = RescueVector::zero();
        let input = RescueVector::zero();
        let expected = RescueVector::from_elems_le_bytes(
            &OUTPUT254[0],
            &OUTPUT254[1],
            &OUTPUT254[2],
            &OUTPUT254[3],
        );
        let real_output = rescue.prp(&key, &input);
        let round_keys = rescue.key_schedule(&key);
        let real_output_with_round_keys = rescue.prp_with_round_keys(&round_keys, &input);
        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    fn test_rescue_perm_on_0_vec_381() {
        let rescue = PRP::<Fr381>::default();
        let key = RescueVector::zero();
        let input = RescueVector::zero();
        let expected = RescueVector::from_elems_le_bytes(
            &OUTPUT381[0],
            &OUTPUT381[1],
            &OUTPUT381[2],
            &OUTPUT381[3],
        );
        let real_output = rescue.prp(&key, &input);
        let round_keys = rescue.key_schedule(&key);
        let real_output_with_round_keys = rescue.prp_with_round_keys(&round_keys, &input);

        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    fn test_rescue_perm_on_0_vec_377() {
        let rescue = PRP::<Fr377>::default();
        let key = RescueVector::zero();
        let input = RescueVector::zero();
        let expected = RescueVector::from_elems_le_bytes(
            &OUTPUT377[0],
            &OUTPUT377[1],
            &OUTPUT377[2],
            &OUTPUT377[3],
        );
        let real_output = rescue.prp(&key, &input);
        let round_keys = rescue.key_schedule(&key);
        let real_output_with_round_keys = rescue.prp_with_round_keys(&round_keys, &input);
        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    fn test_rescue_perm_on_0_vec_761() {
        let rescue = PRP::<Fq377>::default();
        let key = RescueVector::zero();
        let input = RescueVector::zero();
        let expected = RescueVector::from_elems_le_bytes(
            &OUTPUT761[0],
            &OUTPUT761[1],
            &OUTPUT761[2],
            &OUTPUT761[3],
        );
        let real_output = rescue.prp(&key, &input);
        let round_keys = rescue.key_schedule(&key);
        let real_output_with_round_keys = rescue.prp_with_round_keys(&round_keys, &input);
        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    // printing vectors as hex bytes little endian
    // #[test]
    // fn print(){
    // let rescue_hash = RescueBls4::default();
    // println!("KeySchedule:");
    // let keys = rescue_hash.key_schedule(&RescueBls4Vector::zero());
    // for key in keys {
    // for elem in key.vec.iter() {
    // let str: Vec<String> = elem.into_bigint().to_bytes_le().iter().map(|b|
    // format!("0x{:02X},", b)) .collect();
    // println!("{:?}", str.join(" "));
    // }
    // println!("],[");
    // }
    // }
}

#[cfg(test)]
mod test_permutation {
    use crate::rescue::{
        sponge::{RescueCRHF, RescuePRFCore},
        Permutation, RescueParameter, RescueVector, PRP,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as Fr377;
    use ark_ed_on_bls12_381::Fq as Fr381;
    use ark_ed_on_bn254::Fq as Fr254;
    use ark_ff::PrimeField;
    use ark_std::{vec, Zero};

    #[test]
    fn test_round_keys() {
        test_round_keys_helper::<Fr254>();
        test_round_keys_helper::<Fr377>();
        test_round_keys_helper::<Fr381>();
        test_round_keys_helper::<Fq377>();
    }

    fn test_round_keys_helper<F: RescueParameter>() {
        let rescue_perm = PRP::<F>::default();
        let rescue_hash = Permutation::default();
        let zero = RescueVector::zero();
        let keys2 = rescue_perm.key_schedule(&zero);

        // // the following code is used to dump the key schedule to screen
        // // in a sage friendly format
        // for e in keys2.iter() {
        //     for f in e.vec.iter() {
        //         ark_std::println!("permutation_round_key.append(0x{})",
        // f.into_bigint());     }
        // }
        // assert!(false);

        assert_eq!(rescue_hash.round_keys, keys2);
    }

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue761.Sponge([0,0,0,0], 4)
    const OUTPUT761: [[u8; 48]; 3] = [
        [
            0x37, 0xBE, 0x12, 0x7E, 0xDF, 0x9C, 0xBF, 0xCE, 0x78, 0xE1, 0x4F, 0xEB, 0x69, 0xAC,
            0x89, 0x53, 0xE7, 0xC4, 0x8D, 0x89, 0x90, 0x77, 0x64, 0x0D, 0xD0, 0x87, 0x42, 0xDD,
            0x1F, 0x98, 0x30, 0xC8, 0x0F, 0x12, 0x6D, 0x7A, 0x49, 0xD3, 0x22, 0x2E, 0x12, 0xBA,
            0x5B, 0x0E, 0x29, 0xB7, 0x2C, 0x01,
        ],
        [
            0x68, 0xFE, 0x2E, 0x95, 0x57, 0xDA, 0x2E, 0x36, 0xEC, 0xC1, 0xC5, 0x8A, 0x19, 0x50,
            0xD7, 0xBE, 0x11, 0x00, 0x3D, 0x5B, 0xAA, 0x8C, 0xF8, 0x45, 0x6F, 0xDC, 0xE4, 0x1F,
            0xF0, 0x35, 0xC7, 0x62, 0x6A, 0xC2, 0x33, 0xE7, 0x98, 0x9F, 0x26, 0x2A, 0x6E, 0x89,
            0xD5, 0x43, 0x21, 0xF8, 0x67, 0x01,
        ],
        [
            0x84, 0xB4, 0x93, 0x04, 0x3B, 0x23, 0x3A, 0x1B, 0x43, 0xC3, 0x61, 0x61, 0x1B, 0xA0,
            0x59, 0xFB, 0x2E, 0x88, 0x76, 0x62, 0x28, 0xBB, 0x32, 0x6F, 0x27, 0x1C, 0xA9, 0xCA,
            0x60, 0xC1, 0xE0, 0x7A, 0x7D, 0x37, 0x2F, 0x95, 0x75, 0xDD, 0x37, 0x2A, 0x70, 0xD1,
            0xE4, 0x55, 0xDB, 0x50, 0x2F, 0x00,
        ],
    ];

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue254.Sponge([0,0,0,0], 4)
    const OUTPUT254: [[u8; 32]; 3] = [
        [
            0xDD, 0xE7, 0x55, 0x8E, 0x14, 0xF9, 0x4C, 0xEE, 0x9F, 0xCC, 0xB2, 0x02, 0xFC, 0x0E,
            0x54, 0x21, 0xF2, 0xAA, 0xB8, 0x48, 0x05, 0xDB, 0x9B, 0x7A, 0xD2, 0x36, 0xA5, 0xF1,
            0x49, 0x77, 0xB4, 0x17,
        ],
        [
            0x43, 0x5F, 0x99, 0x3C, 0xB7, 0xB3, 0x84, 0x74, 0x4E, 0x80, 0x83, 0xFF, 0x73, 0x20,
            0x07, 0xD9, 0x7B, 0xEC, 0x4B, 0x90, 0x48, 0x1D, 0xFD, 0x72, 0x4C, 0xF0, 0xA5, 0x7C,
            0xDC, 0x68, 0xC0, 0x25,
        ],
        [
            0x2C, 0x7B, 0x21, 0x09, 0x9D, 0x10, 0xE9, 0x5C, 0x36, 0x3E, 0x6D, 0x20, 0x28, 0xBB,
            0xDB, 0x1E, 0xED, 0xF4, 0x22, 0x9B, 0x3A, 0xEE, 0x1E, 0x6F, 0x89, 0x13, 0x3D, 0x1E,
            0x4C, 0xA0, 0xA6, 0x23,
        ],
    ];
    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue377.Sponge([0,0,0,0], 4)
    const OUTPUT377: [[u8; 32]; 3] = [
        [
            0x65, 0xF2, 0xF2, 0x74, 0x15, 0x7A, 0x5A, 0xB5, 0xE0, 0x86, 0x46, 0x9D, 0xAE, 0x27,
            0x29, 0xE0, 0x08, 0x39, 0x0D, 0xA6, 0x44, 0x5E, 0x20, 0x76, 0x23, 0x42, 0xDA, 0xF0,
            0x49, 0xA3, 0x51, 0x02,
        ],
        [
            0x67, 0xB5, 0x6A, 0xBA, 0x4B, 0xB8, 0x0F, 0xE2, 0xFC, 0x3D, 0x7E, 0xFC, 0x70, 0xCA,
            0x3D, 0x1D, 0xAC, 0xDD, 0xEA, 0x62, 0x81, 0xD7, 0x08, 0x0B, 0x38, 0x5F, 0x0A, 0x68,
            0xEC, 0xED, 0x53, 0x02,
        ],
        [
            0x10, 0xC5, 0xA0, 0xA1, 0x8E, 0x8D, 0xBC, 0xAD, 0x99, 0xC3, 0xB4, 0xE9, 0x22, 0xC9,
            0xB1, 0xCF, 0x35, 0x46, 0xE3, 0x52, 0x99, 0x5B, 0xBE, 0x6E, 0x08, 0xFF, 0x4B, 0x2F,
            0xCE, 0xF0, 0xCB, 0x0A,
        ],
    ];

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue381.Sponge([0,0,0,0], 4)
    const OUTPUT381: [[u8; 32]; 3] = [
        [
            0x12, 0x53, 0x24, 0x66, 0x84, 0xA2, 0x4D, 0x2B, 0xC7, 0x28, 0x3E, 0x0F, 0x80, 0xDF,
            0x1A, 0xC3, 0x5B, 0xA1, 0xA9, 0x5B, 0x46, 0x60, 0xBD, 0xED, 0xA6, 0xD1, 0x43, 0xB7,
            0x60, 0xCA, 0x59, 0x0D,
        ],
        [
            0x1B, 0xBE, 0xAB, 0x6C, 0xAB, 0x62, 0xB7, 0xAB, 0x19, 0xDF, 0xFF, 0x4D, 0x73, 0xB5,
            0x78, 0x30, 0x72, 0xC0, 0xC6, 0xDA, 0x1F, 0x10, 0xAD, 0xD1, 0x28, 0x65, 0xB4, 0x94,
            0x6F, 0xAC, 0xE5, 0x4B,
        ],
        [
            0x07, 0x86, 0xBD, 0x9A, 0xB3, 0x35, 0x96, 0x22, 0xF0, 0xE5, 0xEA, 0xCC, 0x9C, 0x79,
            0x89, 0x1F, 0x9D, 0x1D, 0x43, 0x44, 0xCC, 0xA9, 0x9A, 0xB0, 0x0E, 0xC0, 0x57, 0x6B,
            0x07, 0xF8, 0x53, 0x06,
        ],
    ];

    #[test]
    fn test_sponge() {
        test_sponge_helper::<Fr254>();
        test_sponge_helper::<Fr377>();
        test_sponge_helper::<Fr381>();
        test_sponge_helper::<Fq377>();
    }

    fn test_sponge_helper<F: RescueParameter>() {
        let rescue_prp = PRP::default();
        let mut prng = jf_utils::test_rng();
        let e0 = F::rand(&mut prng);
        let e1 = F::rand(&mut prng);
        let e2 = F::rand(&mut prng);
        let e3 = F::rand(&mut prng);
        let e4 = F::rand(&mut prng);
        let e5 = F::rand(&mut prng);

        let input = [e0, e1, e2, e3, e4, e5];

        let output = RescueCRHF::<F>::sponge_no_padding(&input, 1).unwrap()[0];

        let zero = RescueVector::zero();
        let mut state = RescueVector {
            vec: [input[0], input[1], input[2], F::zero()],
        };
        state = rescue_prp.prp(&zero, &state);
        state.add_assign_elems(&input[3..6]);
        state = rescue_prp.prp(&zero, &state);
        assert_eq!(output, state.vec[0]);
    }

    #[test]
    fn test_rescue_hash_on_0_vec() {
        test_rescue_hash_on_0_vec_254();
        test_rescue_hash_on_0_vec_377();
        test_rescue_hash_on_0_vec_381();
        test_rescue_hash_on_0_vec_761()
    }

    fn test_rescue_hash_on_0_vec_254() {
        let input = [Fr254::zero(); 3];
        let expected = vec![
            Fr254::from_le_bytes_mod_order(&OUTPUT254[0]),
            Fr254::from_le_bytes_mod_order(&OUTPUT254[1]),
            Fr254::from_le_bytes_mod_order(&OUTPUT254[2]),
        ];
        let real_output = RescueCRHF::sponge_no_padding(&input, 3).unwrap();
        assert_eq!(real_output, expected);
    }

    fn test_rescue_hash_on_0_vec_377() {
        let input = [Fr377::zero(); 3];
        let expected = vec![
            Fr377::from_le_bytes_mod_order(&OUTPUT377[0]),
            Fr377::from_le_bytes_mod_order(&OUTPUT377[1]),
            Fr377::from_le_bytes_mod_order(&OUTPUT377[2]),
        ];
        let real_output = RescueCRHF::sponge_no_padding(&input, 3).unwrap();
        assert_eq!(real_output, expected);
    }

    fn test_rescue_hash_on_0_vec_381() {
        let input = [Fr381::zero(); 3];
        let expected = vec![
            Fr381::from_le_bytes_mod_order(&OUTPUT381[0]),
            Fr381::from_le_bytes_mod_order(&OUTPUT381[1]),
            Fr381::from_le_bytes_mod_order(&OUTPUT381[2]),
        ];
        let real_output = RescueCRHF::sponge_no_padding(&input, 3).unwrap();
        assert_eq!(real_output, expected);
    }

    fn test_rescue_hash_on_0_vec_761() {
        let input = [Fq377::zero(); 3];
        let expected = vec![
            Fq377::from_le_bytes_mod_order(&OUTPUT761[0]),
            Fq377::from_le_bytes_mod_order(&OUTPUT761[1]),
            Fq377::from_le_bytes_mod_order(&OUTPUT761[2]),
        ];
        let real_output = RescueCRHF::sponge_no_padding(&input, 3).unwrap();
        assert_eq!(real_output, expected);
    }

    #[test]
    fn test_fsks_no_padding_errors() {
        test_fsks_no_padding_errors_helper::<Fr254>();
        test_fsks_no_padding_errors_helper::<Fr377>();
        test_fsks_no_padding_errors_helper::<Fr381>();
        test_fsks_no_padding_errors_helper::<Fq377>();
    }
    fn test_fsks_no_padding_errors_helper<F: RescueParameter>() {
        let key = F::rand(&mut jf_utils::test_rng());
        let input = vec![F::from(9u64); 4];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );
        let input = vec![F::from(9u64); 12];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );

        // test should panic because number of inputs is not multiple of 3
        let input = vec![F::from(9u64); 10];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );
        let input = vec![F::from(9u64)];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );

        let input = vec![];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );
    }

    #[test]
    fn test_variable_output_sponge_and_fsks() {
        test_variable_output_sponge_and_fsks_helper::<Fr254>();
        test_variable_output_sponge_and_fsks_helper::<Fr377>();
        test_variable_output_sponge_and_fsks_helper::<Fr381>();
        test_variable_output_sponge_and_fsks_helper::<Fq377>();
    }
    fn test_variable_output_sponge_and_fsks_helper<F: RescueParameter>() {
        let input = [F::zero(), F::one(), F::zero()];
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 0).len(), 0);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 1).len(), 1);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 2).len(), 2);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 3).len(), 3);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 10).len(), 10);

        assert_eq!(RescueCRHF::sponge_no_padding(&input, 0).unwrap().len(), 0);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 1).unwrap().len(), 1);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 2).unwrap().len(), 2);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 3).unwrap().len(), 3);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 10).unwrap().len(), 10);

        let key = F::rand(&mut jf_utils::test_rng());
        let input = [F::zero(), F::one(), F::zero(), F::zero()];
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
    }
}
