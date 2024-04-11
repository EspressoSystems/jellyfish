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
            type MembershipProof = MerkleProof<E, I, T, ARITY>;
            // TODO(Chengyu): implement batch membership proof
            type BatchMembershipProof = ();
            type Commitment = MerkleTreeCommitment<T>;

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
                MerkleTreeCommitment::new(self.root.value(), self.height, self.num_leaves)
            }

            fn lookup(
                &self,
                pos: impl Borrow<Self::Index>,
            ) -> LookupResult<&Self::Element, Self::MembershipProof, ()> {
                let pos = pos.borrow();
                let traversal_path = pos.to_traversal_path(self.height);
                match self.root.lookup_internal(self.height, &traversal_path) {
                    LookupResult::Ok(value, proof) => {
                        LookupResult::Ok(&value, MerkleProof::new(pos.clone(), proof))
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(_) => LookupResult::NotFound(()),
                }
            }

            fn verify(
                root: impl Borrow<Self::NodeValue>,
                pos: impl Borrow<Self::Index>,
                proof: impl Borrow<Self::MembershipProof>,
            ) -> Result<VerificationResult, MerkleTreeError> {
                if *pos.borrow() != proof.borrow().pos {
                    return Ok(Err(())); // invalid proof for the given pos
                }
                proof.borrow().verify_membership_proof::<H>(root.borrow())
            }

            fn iter(&self) -> MerkleTreeIter<E, I, T> {
                MerkleTreeIter::new(&self.root)
            }
        }

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

/// Macro for generating a forgetable merkle tree implementation
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
            fn from_commitment(com: impl Borrow<Self::Commitment>) -> Self {
                let com = com.borrow();
                $name {
                    root: Arc::new(MerkleNode::ForgettenSubtree {
                        value: com.digest(),
                    }),
                    height: com.height(),
                    num_leaves: com.size(),
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
                    LookupResult::Ok(elem, proof) => {
                        LookupResult::Ok(elem, MerkleProof::new(pos.clone(), proof))
                    },
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
                let proof = proof.borrow();
                let traversal_path = pos.borrow().to_traversal_path(self.height);
                if let MerkleNode::<E, I, T>::Leaf {
                    value: _,
                    pos,
                    elem,
                } = &proof.proof[0]
                {
                    if !elem.eq(element.borrow()) {
                        return Err(MerkleTreeError::InconsistentStructureError(
                            "Element does not match the proof.".to_string(),
                        ));
                    }
                    let proof_leaf_value = H::digest_leaf(pos, elem)?;
                    let mut path_values = vec![proof_leaf_value];
                    traversal_path.iter().zip(proof.proof.iter().skip(1)).fold(
                        Ok(proof_leaf_value),
                        |result, (branch, node)| -> Result<T, MerkleTreeError> {
                            match result {
                                Ok(val) => match node {
                                    MerkleNode::Branch { value: _, children } => {
                                        let mut data: Vec<_> =
                                            children.iter().map(|node| node.value()).collect();
                                        data[*branch] = val;
                                        let digest = H::digest(&data)?;
                                        path_values.push(digest);
                                        Ok(digest)
                                    },
                                    _ => Err(MerkleTreeError::InconsistentStructureError(
                                        "Incompatible proof for this merkle tree".to_string(),
                                    )),
                                },
                                Err(e) => Err(e),
                            }
                        },
                    )?;
                    self.root = self.root.remember_internal::<H, ARITY>(
                        self.height,
                        &traversal_path,
                        &path_values,
                        &proof.proof,
                    )?;
                    Ok(())
                } else {
                    Err(MerkleTreeError::InconsistentStructureError(
                        "Invalid proof type".to_string(),
                    ))
                }
            }
        }
    };
}

/// Macros for implementing ToTreversalPath for primitive types
#[macro_export]
macro_rules! impl_to_traversal_path_primitives {
    ($t: ty) => {
        impl<const ARITY: usize> ToTraversalPath<ARITY> for $t {
            fn to_traversal_path(&self, height: usize) -> Vec<usize> {
                let mut pos = *self as u64;
                let mut ret = vec![];
                for _i in 0..height {
                    ret.push((pos % (ARITY as u64)) as usize);
                    pos /= ARITY as u64;
                }
                ret
            }
        }
    };
}

/// Macros for implementing ToTreversalPath for BigUint types
#[macro_export]
macro_rules! impl_to_traversal_path_biguint {
    ($t: ty) => {
        impl<const ARITY: usize> ToTraversalPath<ARITY> for $t {
            fn to_traversal_path(&self, height: usize) -> Vec<usize> {
                let mut pos: BigUint = <Self as Into<BigUint>>::into(self.clone());
                let mut ret = vec![];
                for _i in 0..height {
                    ret.push((&pos % ARITY).to_usize().unwrap());
                    pos /= ARITY;
                }
                ret
            }
        }
    };
}
