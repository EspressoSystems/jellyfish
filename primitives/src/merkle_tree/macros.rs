// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Useful macros

/// Macro for generating a standard merkle tree implementation
#[macro_export]
macro_rules! impl_merkle_tree_scheme {
    ($name: ident, $builder: ident) => {
        /// A standard append only Merkle tree implementation
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(
            bound = "E: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize,
                     I: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize,"
        )]
        pub struct $name<E, H, I, Arity, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index,
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
            I: Index + From<u64> + ToTraversalPath<Arity>,
            Arity: Unsigned,
            T: NodeValue,
        {
            type Element = E;
            type Index = I;
            type NodeValue = T;
            type MembershipProof = MerkleProof<E, I, T, Arity>;
            // TODO(Chengyu): implement batch membership proof
            type BatchMembershipProof = ();
            type Commitment = MerkleTreeCommitment<T>;

            const ARITY: usize = Arity::USIZE;

            fn from_elems(
                height: usize,
                elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
            ) -> Result<Self, PrimitivesError> {
                let (root, num_leaves) = $builder::<E, H, I, Arity, T>(height, elems)?;
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

            fn commitment(&self) -> Self::Commitment {
                MerkleTreeCommitment::new(self.root.value(), self.height, self.num_leaves)
            }

            fn lookup(
                &self,
                pos: impl Borrow<Self::Index>,
            ) -> LookupResult<Self::Element, Self::MembershipProof, ()> {
                let pos = pos.borrow();
                let traversal_path = pos.to_traversal_path(self.height);
                match self.root.lookup_internal(self.height, &traversal_path) {
                    LookupResult::Ok(value, proof) => {
                        LookupResult::Ok(value, MerkleProof::new(pos.clone(), proof))
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(_) => LookupResult::NotFound(()),
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
                proof.verify_membership_proof::<H>(&self.root.value())
            }
        }
    };
}

/// Macro for generating a forgetable merkle tree implementation
#[macro_export]
macro_rules! impl_forgetable_merkle_tree_scheme {
    ($name: ident) => {
        impl<E, H, I, Arity, T> ForgetableMerkleTreeScheme for $name<E, H, I, Arity, T>
        where
            E: Element,
            H: DigestAlgorithm<E, I, T>,
            I: Index + From<u64> + ToTraversalPath<Arity>,
            Arity: Unsigned,
            T: NodeValue,
        {
            fn from_commitment(com: impl Borrow<Self::Commitment>) -> Self {
                let com = com.borrow();
                $name {
                    root: Box::new(MerkleNode::ForgettenSubtree {
                        value: com.digest(),
                    }),
                    height: com.height(),
                    num_leaves: com.size(),
                    _phantom_h: PhantomData,
                    _phantom_ta: PhantomData,
                }
            }

            fn forget(
                &mut self,
                pos: Self::Index,
            ) -> LookupResult<Self::Element, Self::MembershipProof, ()> {
                let traversal_path = pos.to_traversal_path(self.height);
                match self.root.forget_internal(self.height, &traversal_path) {
                    LookupResult::Ok(elem, proof) => {
                        LookupResult::Ok(elem, MerkleProof::new(pos, proof))
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(_) => LookupResult::NotFound(()),
                }
            }

            fn remember(
                &mut self,
                pos: Self::Index,
                element: impl Borrow<Self::Element>,
                proof: impl Borrow<Self::MembershipProof>,
            ) -> Result<(), PrimitivesError> {
                let proof = proof.borrow();
                let traversal_path = pos.to_traversal_path(self.height);
                if let MerkleNode::<E, I, T>::Leaf {
                    value: _,
                    pos,
                    elem,
                } = &proof.proof[0]
                {
                    if !elem.eq(element.borrow()) {
                        return Err(PrimitivesError::ParameterError(
                            "Element does not match the proof.".to_string(),
                        ));
                    }
                    let proof_leaf_value = H::digest_leaf(pos, elem);
                    let mut path_values = vec![proof_leaf_value];
                    traversal_path.iter().zip(proof.proof.iter().skip(1)).fold(
                        Ok(proof_leaf_value),
                        |result, (branch, node)| -> Result<T, PrimitivesError> {
                            match result {
                                Ok(val) => match node {
                                    MerkleNode::Branch { value: _, children } => {
                                        let mut data: Vec<_> =
                                            children.iter().map(|node| node.value()).collect();
                                        data[*branch] = val;
                                        let digest = H::digest(&data);
                                        path_values.push(digest);
                                        Ok(digest)
                                    },
                                    _ => Err(PrimitivesError::ParameterError(
                                        "Incompatible proof for this merkle tree".to_string(),
                                    )),
                                },
                                Err(e) => Err(e),
                            }
                        },
                    )?;
                    self.root.remember_internal::<H, Arity>(
                        self.height,
                        &traversal_path,
                        &path_values,
                        &proof.proof,
                    )
                } else {
                    Err(PrimitivesError::ParameterError(
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
        impl<Arity: Unsigned> ToTraversalPath<Arity> for $t {
            fn to_traversal_path(&self, height: usize) -> Vec<usize> {
                let mut pos = *self as u64;
                let mut ret = vec![];
                for _i in 0..height {
                    ret.push((pos % (Arity::to_u64())).to_usize().unwrap());
                    pos /= Arity::to_u64();
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
        impl<Arity: Unsigned> ToTraversalPath<Arity> for $t {
            fn to_traversal_path(&self, height: usize) -> Vec<usize> {
                let mut pos: BigUint = <Self as Into<BigUint>>::into(self.clone());
                let mut ret = vec![];
                for _i in 0..height {
                    ret.push((&pos % (Arity::to_u64())).to_usize().unwrap());
                    pos /= Arity::to_u64();
                }
                ret
            }
        }
    };
}
