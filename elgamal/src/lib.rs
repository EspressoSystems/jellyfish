// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implements the ElGamal encryption scheme.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
extern crate alloc;

use ark_ec::{
    twisted_edwards::{Affine, Projective, TECurveConfig as Config},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{Field, UniformRand};
use ark_serialize::*;
use ark_std::{
    hash::{Hash, Hasher},
    rand::{CryptoRng, Rng, RngCore},
    vec,
    vec::Vec,
    string::ToString,
};
use displaydoc::Display;
use jf_rescue::{Permutation, RescueParameter, RescueVector, PRP, STATE_SIZE};
use zeroize::Zeroize;

/// Error representing invalid parameters.
#[derive(Display, Debug)]
pub struct ParameterError(String);

// ======================= Structures =======================

/// Represents an encryption key.
#[derive(CanonicalSerialize, CanonicalDeserialize, Zeroize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    Eq(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct EncKey<P: Config> {
    pub(crate) key: Projective<P>,
}

impl<P: Config> Hash for EncKey<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.key.into_affine(), state)
    }
}

impl<P: Config> PartialEq for EncKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.key.into_affine() == other.key.into_affine()
    }
}

/// Represents a decryption key.
#[derive(Zeroize, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config")
)]
pub(crate) struct DecKey<P: Config> {
    key: P::ScalarField,
}

impl<P: Config> Drop for DecKey<P> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Represents a key pair (encryption and decryption keys).
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config")
)]
pub struct KeyPair<P: Config> {
    pub(crate) enc: EncKey<P>,
    dec: DecKey<P>,
}

/// Represents the ciphertext resulting from encryption.
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config"),
    Eq(bound = "P: Config"),
    Hash(bound = "P: Config")
)]
pub struct Ciphertext<P: Config> {
    pub(crate) ephemeral: EncKey<P>,
    pub(crate) data: Vec<P::BaseField>,
}

// ======================= Implementations =======================

impl<P: Config> KeyPair<P> {
    /// Generates a new key pair using the provided random number generator.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let dec = DecKey {
            key: P::ScalarField::rand(rng),
        };
        let enc = EncKey::from(&dec);
        KeyPair { enc, dec }
    }

    /// Returns the encryption key reference.
    pub fn enc_key_ref(&self) -> &EncKey<P> {
        &self.enc
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt<F: RescueParameter>(&self, ctext: &Ciphertext<P>) -> Vec<F>
    where
        P: Config<BaseField = F>,
    {
        self.dec.decrypt(ctext)
    }
}

impl<P: Config> EncKey<P> {
    /// Encrypts the given message using the provided randomness.
    pub fn deterministic_encrypt<F, R>(
        &self,
        randomness: P::ScalarField,
        msg: &[F],
    ) -> Ciphertext<P>
    where
        F: RescueParameter,
        P: Config<BaseField = F>,
    {
        let ephemeral_key_pair = KeyPair::from(DecKey { key: randomness });
        self.compute_ciphertext(ephemeral_key_pair, msg)
    }

    /// Encrypts the message using a randomly generated ephemeral key pair.
    pub fn encrypt<F, R>(&self, rng: &mut R, msg: &[F]) -> Ciphertext<P>
    where
        F: RescueParameter,
        P: Config<BaseField = F>,
        R: CryptoRng + RngCore,
    {
        let ephemeral_key_pair = KeyPair::generate(rng);
        self.compute_ciphertext(ephemeral_key_pair, msg)
    }

    /// Computes the ciphertext using an ephemeral key pair.
    fn compute_ciphertext<F>(&self, ephemeral_key_pair: KeyPair<P>, msg: &[F]) -> Ciphertext<P>
    where
        F: RescueParameter,
        P: Config<BaseField = F>,
    {
        let shared_key = (self.key * ephemeral_key_pair.dec.key).into_affine();
        let perm = Permutation::default();
        let key = perm.eval(&RescueVector::from(&[
            shared_key.x,
            shared_key.y,
            F::zero(),
            F::zero(),
        ]));
        Ciphertext {
            ephemeral: ephemeral_key_pair.enc,
            data: apply_counter_mode_stream::<F>(&key, msg, &F::zero(), Direction::Encrypt),
        }
    }
}

impl<P: Config> DecKey<P> {
    /// Decrypts the given ciphertext.
    fn decrypt<F>(&self, ctext: &Ciphertext<P>) -> Vec<F>
    where
        F: RescueParameter,
        P: Config<BaseField = F>,
    {
        let shared_key = (ctext.ephemeral.key * self.key).into_affine();
        let perm = Permutation::default();
        let key = perm.eval(&RescueVector::from(&[
            shared_key.x,
            shared_key.y,
            F::zero(),
            F::zero(),
        ]));
        apply_counter_mode_stream::<F>(&key, &ctext.data, &F::zero(), Direction::Decrypt)
    }
}

impl<P> From<&DecKey<P>> for EncKey<P>
where
    P: Config,
{
    fn from(dec: &DecKey<P>) -> Self {
        let mut point = Projective::<P>::generator();
        point *= dec.key;
        Self { key: point }
    }
}

// ======================= Helper Functions =======================

/// Applies counter-mode encryption or decryption on the given data.
pub(crate) fn apply_counter_mode_stream<F>(
    key: &RescueVector<F>,
    data: &[F],
    nonce: &F,
    direction: Direction,
) -> Vec<F>
where
    F: RescueParameter,
{
    let prp = PRP::default();
    let round_keys = prp.key_schedule(key);

    let mut output = data.to_vec();
    pad_with_zeros(&mut output, STATE_SIZE);

    output
        .chunks_exact_mut(STATE_SIZE)
        .enumerate()
        .for_each(|(idx, chunk)| {
            let stream_chunk = prp.prp_with_round_keys(
                &round_keys,
                &RescueVector::from(&[
                    nonce.add(F::from(idx as u64)),
                    F::zero(),
                    F::zero(),
                    F::zero(),
                ]),
            );

            chunk.iter_mut().zip(stream_chunk.elems()).for_each(|(out, stream)| match direction {
                Direction::Encrypt => out.add_assign(stream),
                Direction::Decrypt => out.sub_assign(stream),
            });
        });

    output.truncate(data.len());
    output
}

#[inline]
fn pad_with_zeros<F: Field>(vec: &mut Vec<F>, multiple: usize) {
    let len = vec.len();
    let new_len = (len + multiple - 1) / multiple * multiple;
    vec.resize(new_len, F::zero());
}

/// Represents the direction of operation (encryption or decryption).
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

// ======================= Tests =======================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_377::{EdwardsConfig, Fq};
    use ark_std::test_rng;

    #[test]
    fn test_keypair_generation() {
        let mut rng = test_rng();
        let keypair = KeyPair::<EdwardsConfig>::generate(&mut rng);
        assert!(keypair.enc_key_ref().key != Projective::<EdwardsConfig>::zero());
    }

    #[test]
    fn test_encryption_decryption() {
        let mut rng = test_rng();
        let keypair = KeyPair::<EdwardsConfig>::generate(&mut rng);

        let message: Vec<Fq> = (0..10).map(|_| Fq::rand(&mut rng)).collect();
        let ciphertext = keypair.enc_key_ref().encrypt(&mut rng, &message);

        let decrypted_message = keypair.decrypt(&ciphertext);
        assert_eq!(message, decrypted_message);
    }
}
