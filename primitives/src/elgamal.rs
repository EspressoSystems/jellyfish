// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implements the ElGamal encryption scheme.

use crate::{
    elgamal::Direction::{Decrypt, Encrypt},
    errors::PrimitivesError,
    rescue::{Permutation, RescueParameter, RescueVector, PRP, STATE_SIZE},
};
use ark_ec::{
    twisted_edwards::{Affine, Projective, TECurveConfig as Config},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::UniformRand;
use ark_serialize::*;
use ark_std::{
    hash::{Hash, Hasher},
    rand::{CryptoRng, Rng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_utils::pad_with_zeros;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zeroize::Zeroize;

// =====================================================
// encrypt key
// =====================================================
/// Encryption key for encryption scheme
#[derive(CanonicalSerialize, CanonicalDeserialize, Zeroize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    Eq(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct EncKey<P>
where
    P: Config,
{
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

// =====================================================
// decrypt key
// =====================================================
/// Decryption key for encryption scheme
#[derive(Zeroize, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config")
)]
pub(crate) struct DecKey<P>
where
    P: Config,
{
    key: P::ScalarField,
}

impl<P: Config> Drop for DecKey<P> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// =====================================================
// key pair
// =====================================================

#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config")
)]
/// KeyPair structure for encryption scheme
pub struct KeyPair<P>
where
    P: Config,
{
    pub(crate) enc: EncKey<P>,
    dec: DecKey<P>,
}

// =====================================================
// ciphertext
// =====================================================
/// Public encryption cipher text
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config"),
    Eq(bound = "P: Config"),
    Hash(bound = "P: Config")
)]
pub struct Ciphertext<P>
where
    P: Config,
{
    pub(crate) ephemeral: EncKey<P>,
    pub(crate) data: Vec<P::BaseField>,
}

impl<P> Ciphertext<P>
where
    P: Config,
{
    /// Flatten out the ciphertext into a vector of scalars
    pub fn to_scalars(&self) -> Vec<P::BaseField> {
        let mut result = vec![];
        let (x, y) = (&self.ephemeral).into();
        result.push(x);
        result.push(y);
        result.extend_from_slice(&self.data);
        result
    }

    /// Reconstruct the ciphertext from a list of scalars.
    pub fn from_scalars(scalars: &[P::BaseField]) -> Result<Self, PrimitivesError> {
        if scalars.len() < 2 {
            return Err(PrimitivesError::ParameterError(
                "At least 2 scalars in length for ciphertext".to_string(),
            ));
        }
        let key = Affine::new(scalars[0], scalars[1]);

        let ephemeral = EncKey {
            key: key.into_group(),
        };
        let mut data = vec![];
        data.extend_from_slice(&scalars[2..]);
        Ok(Self { ephemeral, data })
    }
}

// =====================================================
// end of definitions
// =====================================================

impl<P> KeyPair<P>
where
    P: Config,
{
    /// Key generation algorithm for public key encryption scheme
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KeyPair<P> {
        let dec = DecKey {
            key: P::ScalarField::rand(rng),
        };
        let enc = EncKey::from(&dec);
        KeyPair { enc, dec }
    }

    /// Get decryption key reference
    pub(crate) fn dec_key_ref(&self) -> &DecKey<P> {
        &self.dec
    }

    /// Get encryption key
    pub fn enc_key(&self) -> EncKey<P> {
        self.enc.clone()
    }

    /// Get encryption key reference
    pub fn enc_key_ref(&self) -> &EncKey<P> {
        &self.enc
    }
}

impl<P> From<DecKey<P>> for KeyPair<P>
where
    P: Config,
{
    fn from(dec: DecKey<P>) -> Self {
        let enc = EncKey::from(&dec);
        KeyPair { enc, dec }
    }
}

/// Sample a random public key with unknown associated secret key
impl<P: Config> UniformRand for EncKey<P> {
    fn rand<R>(rng: &mut R) -> Self
    where
        R: Rng + RngCore + ?Sized,
    {
        EncKey {
            key: Projective::<P>::rand(rng),
        }
    }
}

impl<F, P> EncKey<P>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    fn compute_cipher_text_from_ephemeral_key_pair(
        &self,
        ephemeral_key_pair: KeyPair<P>,
        msg: &[F],
    ) -> Ciphertext<P> {
        let shared_key = (self.key * ephemeral_key_pair.dec_key_ref().key).into_affine();
        let perm = Permutation::default();
        // TODO check if ok to use (x,y,0,0) as a key, since
        // key = perm(x,y,0,0) doesn't buy us anything.
        let key = perm.eval(&RescueVector::from(&[
            shared_key.x,
            shared_key.y,
            F::zero(),
            F::zero(),
        ]));
        // since key was just sampled and to be used only once, we can allow NONCE = 0
        Ciphertext {
            ephemeral: ephemeral_key_pair.enc_key(),
            data: apply_counter_mode_stream::<F>(&key, msg, &F::zero(), Encrypt),
        }
    }

    /// Public key encryption function with pre-sampled randomness
    /// * `r` - randomness
    /// * `msg` - plaintext
    /// * `returns` - Ciphertext
    pub fn deterministic_encrypt(&self, r: P::ScalarField, msg: &[F]) -> Ciphertext<P> {
        let ephemeral_key_pair = KeyPair::from(DecKey { key: r });
        self.compute_cipher_text_from_ephemeral_key_pair(ephemeral_key_pair, msg)
    }

    /// Public key encryption function
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        msg: &[P::BaseField],
    ) -> Ciphertext<P> {
        let ephemeral_key_pair = KeyPair::generate(prng);
        self.compute_cipher_text_from_ephemeral_key_pair(ephemeral_key_pair, msg)
    }
}

impl<F, P> DecKey<P>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    /// Decryption function
    fn decrypt(&self, ctext: &Ciphertext<P>) -> Vec<P::BaseField> {
        let perm = Permutation::default();
        let shared_key = (ctext.ephemeral.key * self.key).into_affine();
        let key = perm.eval(&RescueVector::from(&[
            shared_key.x,
            shared_key.y,
            F::zero(),
            F::zero(),
        ]));
        // since key was just samples and to be used only once, we can have NONCE = 0
        apply_counter_mode_stream::<F>(&key, ctext.data.as_slice(), &F::zero(), Decrypt)
    }
}

impl<P> From<&DecKey<P>> for EncKey<P>
where
    P: Config,
{
    fn from(dec_key: &DecKey<P>) -> Self {
        let mut point = Projective::<P>::generator();
        point *= dec_key.key;
        Self { key: point }
    }
}

impl<F, P> KeyPair<P>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    /// Decryption function
    pub fn decrypt(&self, ctext: &Ciphertext<P>) -> Vec<F> {
        self.dec.decrypt(ctext)
    }
}

pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

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
    // compute stream
    let mut output = data.to_vec();
    // temporarily append dummy padding element
    pad_with_zeros(&mut output, STATE_SIZE);

    let round_fn = |(idx, output_chunk): (usize, &mut [F])| {
        let stream_chunk = prp.prp_with_round_keys(
            &round_keys,
            &RescueVector::from(&[
                nonce.add(F::from(idx as u64)),
                F::zero(),
                F::zero(),
                F::zero(),
            ]),
        );
        for (output_elem, stream_elem) in output_chunk.iter_mut().zip(stream_chunk.elems().iter()) {
            match direction {
                Direction::Encrypt => output_elem.add_assign(stream_elem),
                Direction::Decrypt => output_elem.sub_assign(stream_elem),
            }
        }
    };
    #[cfg(feature = "parallel")]
    {
        output
            .par_chunks_exact_mut(STATE_SIZE)
            .enumerate()
            .for_each(round_fn);
    }
    #[cfg(not(feature = "parallel"))]
    {
        output
            .chunks_exact_mut(STATE_SIZE)
            .enumerate()
            .for_each(round_fn);
    }
    // remove dummy padding elements
    output.truncate(data.len());
    output
}

#[cfg(test)]
mod test {
    use super::{Ciphertext, DecKey, EncKey, KeyPair, UniformRand};
    use ark_ed_on_bls12_377::{EdwardsConfig as ParamEd377, Fq as FqEd377, Fr as FrEd377};
    use ark_ed_on_bls12_381::{EdwardsConfig as ParamEd381, Fq as FqEd381, Fr as FrEd381};
    use ark_ed_on_bls12_381_bandersnatch::{
        EdwardsConfig as ParamEd381b, Fq as FqEd381b, Fr as FrEd381b,
    };
    use ark_ed_on_bn254::{EdwardsConfig as ParamEd254, Fq as FqEd254, Fr as FrEd254};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{vec, vec::Vec};

    macro_rules! test_enc_and_dec {
        ($param: tt, $base_field:tt, $scalar_field: tt) => {
            let mut rng = jf_utils::test_rng();
            let keypair: KeyPair<$param> = KeyPair::generate(&mut rng);
            let mut data = vec![];
            let mut i = 0;

            let pub_key = keypair.enc_key_ref();

            loop {
                if i == 17 {
                    break;
                }

                let ctext1 = pub_key.encrypt(&mut rng, &data);
                let decrypted1 = keypair.decrypt(&ctext1);
                assert_eq!(&data, decrypted1.as_slice());
                let decrypted1 = keypair.dec_key_ref().decrypt(&ctext1);
                assert_eq!(&data, decrypted1.as_slice());

                let ctext2 = pub_key.deterministic_encrypt($scalar_field::rand(&mut rng), &data);
                let decrypted2 = keypair.decrypt(&ctext2);
                assert_eq!(&data, decrypted2.as_slice());

                data.push($base_field::rand(&mut rng));
                i += 1;
            }
        };
    }

    #[test]
    fn test_enc_and_dec() {
        test_enc_and_dec!(ParamEd254, FqEd254, FrEd254);
        test_enc_and_dec!(ParamEd377, FqEd377, FrEd377);
        test_enc_and_dec!(ParamEd381, FqEd381, FrEd381);
        test_enc_and_dec!(ParamEd381b, FqEd381b, FrEd381b);
    }

    macro_rules! test_serdes {
        ($param: tt, $base_field:tt, $scalar_field: tt) => {
            let mut rng = jf_utils::test_rng();
            let keypair = KeyPair::<$param>::generate(&mut rng);
            let msg = vec![$base_field::rand(&mut rng)];
            let ct = keypair.enc_key().encrypt(&mut rng, &msg[..]);

            let mut ser_bytes: Vec<u8> = Vec::new();
            keypair.serialize_compressed(&mut ser_bytes).unwrap();
            let de: KeyPair<$param> = KeyPair::deserialize_compressed(&ser_bytes[..]).unwrap();
            assert_eq!(de, keypair);

            let mut ser_bytes: Vec<u8> = Vec::new();
            keypair.enc.serialize_compressed(&mut ser_bytes).unwrap();
            let de: EncKey<$param> = EncKey::deserialize_compressed(&ser_bytes[..]).unwrap();
            assert_eq!(keypair.enc, de);

            let mut ser_bytes: Vec<u8> = Vec::new();
            keypair.dec.serialize_compressed(&mut ser_bytes).unwrap();
            let de: DecKey<$param> = DecKey::deserialize_compressed(&ser_bytes[..]).unwrap();
            assert_eq!(keypair.dec, de);

            let mut ser_bytes: Vec<u8> = Vec::new();
            ct.serialize_compressed(&mut ser_bytes).unwrap();
            let de: Ciphertext<$param> =
                Ciphertext::deserialize_compressed(&ser_bytes[..]).unwrap();
            assert_eq!(ct, de);
        };
    }

    #[test]
    fn test_serde() {
        test_serdes!(ParamEd254, FqEd254, FrEd254);
        test_serdes!(ParamEd377, FqEd377, FrEd377);
        test_serdes!(ParamEd381, FqEd381, FrEd381);
        test_serdes!(ParamEd381b, FqEd381b, FrEd381b);
    }
}
