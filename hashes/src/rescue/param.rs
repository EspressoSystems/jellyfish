use ark_ff::PrimeField;

/// The state size of rescue hash.
pub const STATE_SIZE: usize = 4;
/// The rate of rescue hash.
pub const RATE: usize = 3;

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
pub trait RescueParameter: PrimeField {
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
