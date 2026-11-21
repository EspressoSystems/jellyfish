// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Various serialization functions.

use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

/// Serializers for elements that are Ark-Works serializable but not serde
/// serializable.
///
/// Many cryptographic objects (e.g. finite field elements) are foreign types
/// that we cannot apply [tagged] or `#[derive(Deserialize, Serialize)]` to.
/// Instead, use `#[serde(with = "canonical")]` at the point where the object is
/// used inside a struct or enum definition.
///
/// [tagged]: tagged_base64::tagged
pub mod canonical {
    use super::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::format;
    use serde::{
        de::{Deserializer, Error as DeError},
        ser::{Error as SerError, Serializer},
    };
    use tagged_base64::TaggedBase64;

    pub fn serialize<S: Serializer, T: CanonicalSerialize>(
        elem: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        T::serialize_compressed(elem, &mut bytes)
            .map_err(|e| S::Error::custom(format!("{e:?}")))?;
        Serialize::serialize(&TaggedBase64::new("FIELD", &bytes).unwrap(), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: CanonicalDeserialize>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let tb64 = <TaggedBase64 as Deserialize>::deserialize(deserializer)?;
        if tb64.tag() == "FIELD" {
            T::deserialize_compressed_unchecked(tb64.as_ref())
                .map_err(|e| D::Error::custom(format!("{e:?}")))
        } else {
            Err(D::Error::custom(format!(
                "incorrect tag (expected FIELD, got {})",
                tb64.tag()
            )))
        }
    }
}
