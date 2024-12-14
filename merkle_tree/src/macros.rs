// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Useful macros for implementing Merkle Tree schemes.

/// Macro for generating a standard Merkle tree implementation.
#[macro_export]
macro_rules! impl_merkle_tree_scheme {
    ($name: ident) => {
        /// A standard append-only Merkle tree implementation.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(
            bound = "E: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize,
                     I: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize,"
        )]
        pub struct $name<E, H, I, const ARITY: usize, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index,
            T: NodeValue,
        {
            root: Arc<MerkleNode<E, I, T>>,
            height: usize,
            num_leaves: u64,
            _phantom: PhantomData<H>,
        }

        impl<E, H, I, const ARITY: usize, T> MerkleTreeScheme for $name<E, H, I, ARITY, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + ToTraversalPath<ARITY>,
            T: NodeValue,
        {
            type Element = E;
            type Index = I;
            type NodeValue = T;
            type MembershipProof = MerkleTreeProof<T>;
            type BatchMembershipProof = (); // Placeholder for future implementation.
            type Commitment = T;

            const ARITY: usize = ARITY;

            fn height(&self) -> usize {
                self.height
            }

            fn capacity(&self) -> BigUint {
                pow(BigUint::from(Self::ARITY), self.height)
            }

            fn num_leaves(&self) -> u64 {
                self.num_leaves
            }

            fn commitment(&self) -> Self::Commitment {
                self.root.value()
            }

            fn lookup(
                &self,
                pos: impl Borrow<Self::Index>,
            ) -> LookupResult<&Self::Element, Self::MembershipProof, ()> {
                let pos = pos.borrow();
                let traversal_path = pos.to_traversal_path(self.height);
                match self.root.lookup_internal(self.height, &traversal_path) {
                    LookupResult::Ok(value, proof) => LookupResult::Ok(&value, proof),
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(_) => LookupResult::NotFound(()),
                }
            }

            fn verify(
                commitment: impl Borrow<Self::Commitment>,
                pos: impl Borrow<Self::Index>,
                element: impl Borrow<Self::Element>,
                proof: impl Borrow<Self::MembershipProof>,
            ) -> Result<VerificationResult, MerkleTreeError> {
                crate::internal::verify_merkle_proof::<E, H, I, ARITY, T>(
                    commitment.borrow(),
                    pos.borrow(),
                    Some(element.borrow()),
                    proof.borrow().path_values(),
                )
            }

            fn iter(&self) -> MerkleTreeIter<E, I, T> {
                MerkleTreeIter::new(&self.root)
            }
        }

        // Implementations for iterators.
        impl<'a, E, H, I, const ARITY: usize, T> IntoIterator for &'a $name<E, H, I, ARITY, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + ToTraversalPath<ARITY>,
            T: NodeValue,
        {
            type Item = (&'a I, &'a E);
            type IntoIter = MerkleTreeIter<'a, E, I, T>;

            fn into_iter(self) -> Self::IntoIter {
                MerkleTreeIter::new(&self.root)
            }
        }

        impl<E, H, I, const ARITY: usize, T> IntoIterator for $name<E, H, I, ARITY, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + ToTraversalPath<ARITY>,
            T: NodeValue,
        {
            type Item = (I, E);
            type IntoIter = MerkleTreeIntoIter<E, I, T>;

            fn into_iter(self) -> Self::IntoIter {
                MerkleTreeIntoIter::new(self.root)
            }
        }
    };
}

/// Macro for generating a forgettable Merkle tree implementation.
#[macro_export]
macro_rules! impl_forgetable_merkle_tree_scheme {
    ($name: ident) => {
        impl<E, H, I, const ARITY: usize, T> ForgetableMerkleTreeScheme for $name<E, H, I, ARITY, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + ToTraversalPath<ARITY>,
            T: NodeValue,
        {
            fn from_commitment(
                com: impl Borrow<Self::Commitment>,
                height: usize,
                num_leaves: u64,
            ) -> Self {
                let com = com.borrow();
                $name {
                    root: Arc::new(MerkleNode::ForgottenSubtree { value: com.clone() }),
                    height,
                    num_leaves,
                    _phantom: PhantomData,
                }
            }

            fn forget(
                &mut self,
                pos: impl Borrow<Self::Index>,
            ) -> LookupResult<Self::Element, Self::MembershipProof, ()> {
                let pos = pos.borrow();
                let traversal_path = pos.to_traversal_path(self.height);
                let (new_root, result) = self.root.forget_internal(self.height, &traversal_path);
                self.root = new_root;
                match result {
                    LookupResult::Ok(elem, proof) => LookupResult::Ok(elem, proof),
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(_) => LookupResult::NotFound(()),
                }
            }

            fn remember(
                &mut self,
                pos: impl Borrow<Self::Index>,
                element: impl Borrow<Self::Element>,
                proof: impl Borrow<Self::MembershipProof>,
            ) -> Result<(), MerkleTreeError> {
                let pos = pos.borrow();
                let element = element.borrow();
                let proof = proof.borrow();
                if Self::verify(&self.commitment(), pos, element, proof)?.is_err() {
                    return Err(MerkleTreeError::InconsistentStructureError(
                        "Invalid proof".to_string(),
                    ));
                }
                let traversal_path = pos.to_traversal_path(self.height);
                self.root = self.root.remember_internal::<H, ARITY>(
                    self.height,
                    &traversal_path,
                    pos,
                    Some(element),
                    proof.path_values(),
                )?;
                Ok(())
            }
        }
    };
}

/// Macro for implementing `ToTraversalPath` for primitive integer types.
#[macro_export]
macro_rules! impl_to_traversal_path_primitives {
    ($t: ty) => {
        impl<const ARITY: usize> ToTraversalPath<ARITY> for $t {
            fn to_traversal_path(&self, height: usize) -> Vec<usize> {
                let mut pos = *self as u64;
                (0..height)
                    .map(|_| {
                        let branch = (pos % ARITY as u64) as usize;
                        pos /= ARITY as u64;
                        branch
                    })
                    .collect()
            }
        }
    };
}

/// Macro for implementing `ToTraversalPath` for `BigUint`.
#[macro_export]
macro_rules! impl_to_traversal_path_biguint {
    ($t: ty) => {
        impl<const ARITY: usize> ToTraversalPath<ARITY> for $t {
            fn to_traversal_path(&self, height: usize) -> Vec<usize> {
                let mut pos = self.clone();
                (0..height)
                    .map(|_| {
                        let branch = (&pos % ARITY).to_usize().unwrap();
                        pos /= ARITY;
                        branch
                    })
                    .collect()
            }
        }
    };
}
