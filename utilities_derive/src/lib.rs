// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![no_std]

extern crate proc_macro;

use ark_std::format;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, Item, NestedMeta};

/// Derive serdes for a type which serializes as a binary blob.
///
/// This macro can be used to easily derive friendly serde implementations for a
/// binary type which implements
/// [CanonicalSerialize](ark_serialize::CanonicalSerialize) and
/// [CanonicalDeserialize](ark_serialize::CanonicalDeserialize). This is useful
/// for cryptographic primitives and other types which do not have a
/// human-readable serialization, but which may be embedded in structs with a
/// human-readable serialization. The serde implementations derived by this
/// macro will serialize the type as bytes for binary encodings and as base 64
/// for human readable encodings.
///
/// Specifically, this macro does 4 things when applied to a type definition:
/// * It adds `#[derive(Serialize, Deserialize)]` to the type definition, along
///   with serde attributes to serialize using the
///   [TaggedBlob](../jf_utils/struct.TaggedBlob.html) serialization helper.
/// * It creates an implementation of [Tagged](../jf_utils/trait.Tagged.html)
///   for the type using the specified tag. This tag will be used to identify
///   base 64 strings which represent this type in human-readable encodings.
/// * It creates an implementation of `TryFrom<TaggedBlob<T>>` for the type `T`,
///   which is needed to make the `serde(try_from)` attribute work.
/// * It creates implementations of [Display](ark_std::fmt::Display) and
///   [FromStr](ark_std::str::FromStr) using tagged base 64 as a display format.
///   This allows tagged blob types to be conveniently displayed and read to and
///   from user interfaces in a manner consistent with how they are serialized.
///
/// Usage example:
///
/// ```
/// #[macro_use] extern crate jf_utils_derive;
/// use ark_serialize::*;
///
/// #[tagged_blob("NUL")]
/// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize, /* any other derives */)]
/// pub struct Nullifier(
///     // This type can only be serialied as an opaque, binary blob using ark_serialize.
///     pub(crate) ark_bls12_381::Fr,
/// );
/// ```
///
/// The type Nullifier can now be serialized as binary:
/// ```
/// # use ark_serialize::*;
/// # use ark_std::UniformRand;
/// # use jf_utils_derive::tagged_blob;
/// # use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
/// # #[tagged_blob("NUL")]
/// # #[derive(Clone, CanonicalSerialize, CanonicalDeserialize, /* any other derives */)]
/// # struct Nullifier(ark_bls12_381::Fr);
/// # let nullifier = Nullifier(ark_bls12_381::Fr::rand(&mut ChaChaRng::from_seed([42; 32])));
/// bincode::serialize(&nullifier).unwrap();
/// ```
/// or as base64:
/// ```
/// # use ark_serialize::*;
/// # use ark_std::UniformRand;
/// # use jf_utils_derive::tagged_blob;
/// # use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
/// # #[tagged_blob("NUL")]
/// # #[derive(Clone, CanonicalSerialize, CanonicalDeserialize, /* any other derives */)]
/// # struct Nullifier(ark_bls12_381::Fr);
/// # let nullifier = Nullifier(ark_bls12_381::Fr::rand(&mut ChaChaRng::from_seed([42; 32])));
/// serde_json::to_string(&nullifier).unwrap();
/// ```
/// which will produce a tagged base64 string like
/// "NUL~8oaujwbov8h4eEq7HFpqW6mIXhVbtJGxLUgiKrGpMCoJ".
#[proc_macro_attribute]
pub fn tagged_blob(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as Item);
    let (name, generics) = match &input {
        Item::Struct(item) => (&item.ident, &item.generics),
        Item::Enum(item) => (&item.ident, &item.generics),
        _ => panic!("expected struct or enum"),
    };
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let tag = match args.as_slice() {
        [NestedMeta::Lit(tag)] => tag,
        _ => panic!("tagged_blob takes one argument, the tag, as a string literal"),
    };
    let serde_str = format!("jf_utils::TaggedBlob<{}>", quote!(#name #ty_generics));
    let output = quote! {
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(try_from = #serde_str, into = #serde_str)]
        // Override the inferred bound for Serialize/Deserialize impls. If we're converting to and
        // from CanonicalBytes as an intermediate, the impls should work for any generic parameters.
        #[serde(bound = "")]
        #input

        impl #impl_generics jf_utils::Tagged for #name #ty_generics #where_clause {
            fn tag() -> ark_std::string::String {
                ark_std::string::String::from(#tag)
            }
        }

        impl #impl_generics core::convert::TryFrom<jf_utils::TaggedBlob<Self>>
            for #name #ty_generics
        #where_clause
        {
            type Error = ark_serialize::SerializationError;
            fn try_from(v: jf_utils::TaggedBlob<Self>) -> Result<Self, Self::Error> {
                <Self as CanonicalDeserialize>::deserialize(
                    &*v.bytes().0,
                )
            }
        }

        impl #impl_generics ark_std::fmt::Display for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ark_std::fmt::Formatter<'_>) -> ark_std::fmt::Result {
                ark_std::write!(
                    f, "{}",
                    jf_utils::TaggedBlob::from(self)
                        .tagged_base64()
                        .map_err(|_| ark_std::fmt::Error)?
                )
            }
        }

        impl #impl_generics ark_std::str::FromStr for #name #ty_generics #where_clause {
            type Err = jf_utils::TaggedBlobError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use core::convert::TryFrom;
                Self::try_from(jf_utils::TaggedBlob::from_str(s)?)
                    .map_err(|source| {
                        jf_utils::TaggedBlobError::DeserializationError { source }
                    })
            }
        }
    };
    output.into()
}
