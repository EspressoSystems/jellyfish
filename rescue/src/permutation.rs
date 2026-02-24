//! State of a rescue-based, overwrite-mode cryptographic sponge (compliant with
//! spongefish)
//!
//! # Historical note
//! In 0.2.0 (and earlier versions), we used to have `RescueSponge` which
//! consists of a permutation function and an internal state. `RescueSponge`
//! implements what ark-sponge's `trait CryptographicSponge` (absorb, squeeze
//! etc.) and `Absorb` is implemented on `RescueParameter` config-marker trait
//! for finite field types that support rescue permutation.
//!
//! When we migrate to `spongefish`'s API design, here are the mapping:
//! - `Absorb` -> `Unit` (which can be `u8` or `Fp`)
//! - `CryptographicSponge` -> `DuplexSpongeInterface`
//!   - but we don't manually implement `DuplexSpongeInterface`, instead we
//!     define a new replacement for `RescueSponge` named `RescuePermutation`
//!     which implements `trait Permutation`, and directly use
//!     `DuplexSponge<C:Permutation>` in spongefish
//!
//! Thus the old RescueSponge is now replaced by the new RescueSponge (same
//! name) with the similar duplex sponge APIs, except that by following
//! spongefish's design, the state and the sponge behavior are not implemented
//! on the same struct.

use ark_std::fmt::{self, Debug};
use spongefish::duplex_sponge::{self, DuplexSponge};

use crate::{Permutation, RescueParameter, RescueVector, STATE_SIZE};
use zeroize::Zeroize;

/// Duplex sponge from [`RescuePermutation`]
pub type RescueSponge<F: RescueParameter, const R: usize> = DuplexSponge<RescuePermutation<F, R>>;

/// State of rescue sponge, containing necessary permutation instance.
/// Replacing `RescueSponge`, see module doc.
#[derive(Clone, Default)]
pub struct RescuePermutation<F: RescueParameter, const R: usize> {
    pub(crate) state: RescueVector<F>,
    pub(crate) perm: Permutation<F>,
}

impl<F: RescueParameter, const R: usize> duplex_sponge::Permutation for RescuePermutation<F, R> {
    type U = F;
    const N: usize = STATE_SIZE;
    const R: usize = R;

    fn new(iv: [u8; 32]) -> Self {
        let perm = Permutation::default();
        let mut state = RescueVector::default();
        state.vec[R] = F::from_le_bytes_mod_order(&iv);
        Self { state, perm }
    }

    fn permute(&mut self) {
        self.state = self.perm.eval(&self.state);
    }
}

impl<F: RescueParameter, const R: usize> AsRef<[F]> for RescuePermutation<F, R> {
    fn as_ref(&self) -> &[F] {
        &self.state.vec
    }
}

impl<F: RescueParameter, const R: usize> AsMut<[F]> for RescuePermutation<F, R> {
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state.vec
    }
}

impl<F: RescueParameter, const R: usize> Zeroize for RescuePermutation<F, R> {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl<F: RescueParameter, const R: usize> Debug for RescuePermutation<F, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.state.fmt(f)
    }
}
