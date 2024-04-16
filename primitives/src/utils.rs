// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use crate::elgamal;
use ark_ec::{twisted_edwards::TECurveConfig as Config, CurveGroup};

impl<P> From<&elgamal::EncKey<P>> for (P::BaseField, P::BaseField)
where
    P: Config,
{
    fn from(pk: &elgamal::EncKey<P>) -> Self {
        let point = pk.key.into_affine();
        (point.x, point.y)
    }
}
