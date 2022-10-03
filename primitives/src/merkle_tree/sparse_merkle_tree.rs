// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

// TODO(Chengyu): place holder for future implementation.
impl<E, H, I, LeafArity, TreeArity, F> UniversalMerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    type NonMembershipProof = ();
    type BatchNonMembershipProof = ();

    fn update(
        &mut self,
        pos: Self::IndexType,
        elem: &Self::ElementType,
    ) -> Result<(), PrimitivesError> {
        let branches = Self::index_to_branches(pos, self.height);
        Self::update_node_internal(&mut self.root, self.height, &branches, elem)
    }
}
