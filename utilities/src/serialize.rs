// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Various serialization functions.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tagged_base64::{TaggedBase64, Tb64Error};

/// A helper for converting CanonicalSerde bytes to standard Serde bytes.
/// use this struct as intermediate target instead of directly deriving
/// serde::Serialize/Deserialize to avoid implementation of Visitors.
#[derive(Serialize, Deserialize)]
pub struct CanonicalBytes(pub Vec<u8>);

impl<T: ark_serialize::CanonicalSerialize> From<T> for CanonicalBytes {
    fn from(obj: T) -> CanonicalBytes {
        let mut bytes = Vec::new();
        obj.serialize(&mut bytes)
            .expect("fail to serialize to canonical bytes");
        CanonicalBytes(bytes)
    }
}

// TODO: (alex) improve this code, currently very naive matcher expression
#[macro_export]
macro_rules! deserialize_canonical_bytes {
    ($t:ident) => {
        impl From<CanonicalBytes> for $t {
            fn from(bytes: CanonicalBytes) -> Self {
                ark_serialize::CanonicalDeserialize::deserialize(bytes.0.as_slice())
                    .expect("fail to deserialize canonical bytes")
            }
        }
    };

    ($t:ident < $lt:lifetime >) => {
        impl<$lt> From<CanonicalBytes> for $t<$lt> {
            fn from(bytes: CanonicalBytes) -> Self {
                ark_serialize::CanonicalDeserialize::deserialize(bytes.0.as_slice())
                    .expect("fail to deserialize canonical bytes")
            }
        }
    };
}

/// Trait for types whose serialization is not human-readable.
///
/// Such types have a human-readable tag which is used to identify tagged base
/// 64 blobs representing a serialization of that type.
///
/// Rather than implement this trait manually, it is recommended to use the
/// [macro@tagged_blob] macro to specify a tag for your type. That macro also
/// derives appropriate serde implementations for serializing as an opaque blob.
pub trait Tagged {
    fn tag() -> String;
}

/// Helper type for serializing tagged blobs.
///
/// A type which can only be serialized using ark_serialize (for example,
/// cryptographic primitives) can derive serde implementations using `serde(from
/// = "TaggedBlob<T>", into = "TaggedBlob<T>")`. The serde implementations for
/// TaggedBlob generate either a packed bytes encoding, if the serialization
/// format is binary, or a tagged base 64 encoding, if the serialization format
/// is human-readable.
///
/// Types which are serialized using TaggedBlob can then be embedded as fields
/// in structs which derive serde implementations, and those structs can then be
/// serialized using an efficient binary encoding or a browser-friendly,
/// human-readable encoding like JSON.
///
/// Rather than manually tag types with `serde(from = "TaggedBlob<T>", into =
/// "TaggedBlob<T>")`, it is recommended to use the [macro@tagged_blob] macro,
/// which will automatically add the appropriate serde attributes as well as the
/// necessary [Tagged] and [From] implementations to allow `serde(from)` to
/// work.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct TaggedBlob<T: Tagged> {
    #[serde(with = "tagged_blob")]
    inner: (CanonicalBytes, PhantomData<T>),
}

impl<T: Tagged> TaggedBlob<T> {
    pub fn bytes(&self) -> &CanonicalBytes {
        &self.inner.0
    }

    pub fn tagged_base64(&self) -> Result<TaggedBase64, Tb64Error> {
        TaggedBase64::new(T::tag().as_str(), &self.inner.0 .0)
    }
}

impl<T: Tagged + CanonicalSerialize + CanonicalDeserialize> From<T> for TaggedBlob<T> {
    fn from(v: T) -> Self {
        Self {
            inner: (CanonicalBytes::from(v), Default::default()),
        }
    }
}

impl<T: Tagged + CanonicalSerialize + CanonicalDeserialize> From<&T> for TaggedBlob<T> {
    fn from(v: &T) -> Self {
        let mut bytes = Vec::new();
        v.serialize(&mut bytes)
            .expect("fail to serialize to canonical bytes");
        Self {
            inner: (CanonicalBytes(bytes), Default::default()),
        }
    }
}

#[derive(Debug, Snafu)]
pub enum TaggedBlobError {
    Base64Error {
        #[snafu(source(false))]
        source: Tb64Error,
    },
    DeserializationError {
        source: ark_serialize::SerializationError,
    },
}

impl<T: Tagged> ark_std::str::FromStr for TaggedBlob<T> {
    type Err = TaggedBlobError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tb64 =
            TaggedBase64::parse(s).map_err(|source| TaggedBlobError::Base64Error { source })?;
        if tb64.tag() == T::tag() {
            Ok(Self {
                inner: (CanonicalBytes(tb64.value()), Default::default()),
            })
        } else {
            Err(TaggedBlobError::Base64Error {
                source: Tb64Error::InvalidTag,
            })
        }
    }
}

pub mod tagged_blob {
    use super::*;
    use ark_std::format;
    use serde::{
        de::{Deserializer, Error as DeError},
        ser::{Error as SerError, Serializer},
    };

    pub fn serialize_with_tag<S: Serializer>(
        tag: &str,
        bytes: &CanonicalBytes,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            let string = tagged_base64::to_string(
                &TaggedBase64::new(tag, &bytes.0)
                    .map_err(|err| S::Error::custom(format!("{}", err)))?,
            );
            Serialize::serialize(&string, serializer)
        } else {
            Serialize::serialize(&bytes.0, serializer)
        }
    }

    pub fn serialize<S: Serializer, T: Tagged>(
        v: &(CanonicalBytes, PhantomData<T>),
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_with_tag(T::tag().as_str(), &v.0, serializer)
    }

    pub fn deserialize_with_tag<'de, D: Deserializer<'de>>(
        tag: &str,
        deserializer: D,
    ) -> Result<CanonicalBytes, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            let string = <String as Deserialize>::deserialize(deserializer)?;
            let tb64 =
                TaggedBase64::parse(&string).map_err(|err| D::Error::custom(format!("{}", err)))?;
            if tb64.tag() == tag {
                tb64.value()
            } else {
                return Err(D::Error::custom(format!(
                    "tag mismatch: expected {}, but got {}",
                    tag,
                    tb64.tag()
                )));
            }
        } else {
            <Vec<u8> as Deserialize>::deserialize(deserializer)?
        };
        Ok(CanonicalBytes(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Tagged>(
        deserializer: D,
    ) -> Result<(CanonicalBytes, PhantomData<T>), D::Error> {
        let bytes = deserialize_with_tag(T::tag().as_str(), deserializer)?;
        Ok((bytes, Default::default()))
    }
}

/// Serializers for finite field elements.
///
/// Field elements are typically foreign types that we cannot apply the
/// [macro@tagged_blob] macro to. Instead, use `#[serde(with = "field_elem")]`
/// at the point where the field element is used inside a struct or enum
/// definition.
pub mod field_elem {
    use super::*;
    use ark_std::format;
    use serde::{
        de::{Deserializer, Error as DeError},
        ser::{Error as SerError, Serializer},
    };

    pub fn serialize<S: Serializer, T: CanonicalSerialize>(
        elem: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        T::serialize(elem, &mut bytes).map_err(|err| S::Error::custom(format!("{}", err)))?;
        tagged_blob::serialize_with_tag("FIELD", &CanonicalBytes(bytes), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: CanonicalDeserialize>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes = tagged_blob::deserialize_with_tag("FIELD", deserializer)?;
        T::deserialize(&*bytes.0).map_err(|err| D::Error::custom(format!("{}", err)))
    }
}

extern crate jf_utils_derive;
pub use jf_utils_derive::*;

#[macro_export]
macro_rules! test_serde_default {
    ($struct:tt) => {
        use ark_serialize::*;

        let data = $struct::default();
        let mut ser_bytes: $crate::Vec<u8> = $crate::Vec::new();
        data.serialize(&mut ser_bytes).unwrap();
        let de: $struct = $struct::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, data);
    };
}
