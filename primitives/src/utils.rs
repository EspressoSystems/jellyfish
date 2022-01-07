use crate::{elgamal, schnorr_dsa};
use ark_ec::{ProjectiveCurve, TEModelParameters as Parameters};
use ark_ff::PrimeField;

impl<F, P> From<&schnorr_dsa::VerKey<P>> for (F, F)
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    fn from(vk: &schnorr_dsa::VerKey<P>) -> Self {
        let point = vk.0.into_affine();
        (point.x, point.y)
    }
}

impl<P> From<&elgamal::EncKey<P>> for (P::BaseField, P::BaseField)
where
    P: Parameters + Clone,
{
    fn from(pk: &elgamal::EncKey<P>) -> Self {
        let point = pk.key.into_affine();
        (point.x, point.y)
    }
}
