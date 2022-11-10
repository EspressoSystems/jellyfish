// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Useful macros

/// Macro for generating a standard merkle tree implementation
#[macro_export]
macro_rules! impl_merkle_tree_scheme {
    ($name: ident) => {
        /// A standard append only Merkle tree implementation
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name<E, H, I, Arity, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + From<u64>,
            Arity: Unsigned,
            T: NodeValue,
        {
            root: Box<MerkleNode<E, I, T>>,
            height: usize,
            num_leaves: u64,

            _phantom_h: PhantomData<H>,
            _phantom_ta: PhantomData<Arity>,
        }

        impl<E, H, I, Arity, T> MerkleTreeScheme for $name<E, H, I, Arity, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + From<u64>,
            Arity: Unsigned,
            T: NodeValue,
        {
            type Element = E;
            type Digest = H;
            type Index = I;
            type NodeValue = T;
            type MembershipProof = MerkleProof<E, I, T>;
            // TODO(Chengyu): implement batch membership proof
            type BatchMembershipProof = ();

            const ARITY: usize = Arity::USIZE;

            fn from_elems(
                height: usize,
                elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
            ) -> Result<Self, PrimitivesError> {
                let (root, num_leaves) = build_tree_internal::<E, H, I, Arity, T>(height, elems)?;
                Ok($name {
                    root,
                    height,
                    num_leaves,
                    _phantom_h: PhantomData,
                    _phantom_ta: PhantomData,
                })
            }

            fn height(&self) -> usize {
                self.height
            }

            fn capacity(&self) -> BigUint {
                pow(BigUint::from(Self::ARITY), self.height)
            }

            fn num_leaves(&self) -> u64 {
                self.num_leaves
            }

            fn root(&self) -> T {
                self.root.value()
            }

            fn commitment(&self) -> MerkleCommitment<T> {
                MerkleCommitment {
                    root_value: self.root.value(),
                    height: self.height,
                    num_leaves: self.num_leaves,
                }
            }

            fn lookup(
                &self,
                pos: impl Borrow<Self::Index>,
            ) -> LookupResult<Self::Element, Self::MembershipProof> {
                let pos = pos.borrow();
                let traversal_path = pos.to_traverse_path(self.height, Self::ARITY);
                match self.root.lookup_internal(self.height, &traversal_path) {
                    LookupResult::Ok(value, proof) => LookupResult::Ok(
                        value,
                        MerkleProof {
                            pos: pos.clone(),
                            proof,
                        },
                    ),
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
                }
            }

            fn verify(
                &self,
                pos: impl Borrow<Self::Index>,
                proof: impl Borrow<Self::MembershipProof>,
            ) -> Result<bool, PrimitivesError> {
                let pos = pos.borrow();
                let proof = proof.borrow();
                if self.height != proof.tree_height() - 1 {
                    return Err(PrimitivesError::ParameterError(
                        "Incompatible membership proof for this merkle tree".to_string(),
                    ));
                }
                if *pos != proof.pos {
                    return Err(PrimitivesError::ParameterError(
                        "Inconsistent proof index".to_string(),
                    ));
                }
                proof.verify_membership_proof::<H, Arity>(&self.root())
            }
        }
    };
}
