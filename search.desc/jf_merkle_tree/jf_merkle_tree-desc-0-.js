searchState.loadedDescShard("jf_merkle_tree", 0, "Merkle Tree traits and implementations\nTree ARITY\nMerkle tree that allows insertion at back. Abstracted as a …\nBatch proof\nBatch non membership proof\nMerkle tree commitment\nMerkle tree hash function\nAn element of a Merkle tree.\nMerkle tree element type\nGlorified false\nMerkle tree that allows forget/remember elements from the …\nUniversal Merkle tree that allows forget/remember elements …\nAn index type of a leaf in a Merkle tree.\nIndex type for this merkle tree\nThe result of querying at an index in the tree Typically, …\nMerkle proof\nTrait for a Merkle proof\nBasic functionalities for a merkle tree implementation. …\nAn internal node value type in a Merkle tree.\nInternal and root node value\nNon membership proof for a given index\nThe index is outside the occupied range in the tree, and a …\nThe index is valid but we do not have the leaf in memory\nThe value at the given index, and a proof of validity\nA universal merkle tree that allows non destructive …\nGlorified true\nAn trait for Merkle tree index type.\nA universal merkle tree is abstracted as a random-access …\nImplementation of a typical append only merkle tree\nReturn the maximum allowed number leaves\nReturn a merkle commitment\nDigest a list of values\nDigest an indexed element\nError types\nProvides sample instantiations of merkle tree. E.g. Sparse …\nAssert the lookup result is NotFound. Return a …\nAssert the lookup result is NotInMemory.\nAssert the lookup result is Ok. Return a tuple of element …\nInsert a list of new values at the leftmost available slots\nTrim the leaf at position <code>i</code> from memory, if present. …\nReturns the argument unchanged.\nRebuild a merkle tree from a commitment. Return a tree …\nA convenience wrapper <code>HasherMerkleTree</code> to instantiate …\nExpected height of the Merkle tree.\nReturn the height of this merkle tree\nMacro for generating a forgetable merkle tree …\nMacro for generating a standard merkle tree implementation\nMacros for implementing ToTreversalPath for BigUint types\nMacros for implementing ToTreversalPath for primitive types\nCalls <code>U::from(self)</code>.\nReturn an iterator that iterates through all element that …\nA light weight merkle tree is an append only merkle tree …\nReturns the leaf value given a position\nUseful macros\n“Re-insert” an empty leaf into the tree using its …\nVerify an index is not in this merkle tree\nReturn the current number of leaves\nReturn all values of siblings of this Merkle path\nA persistent remove interface, check …\nA non destructive update interface, check …\nA persistent update_with interface, check …\nPrelude. Also provides sample instantiations of merkle …\nInsert a new value at the leftmost available slot\n“Re-insert” a leaf into the tree using its proof. …\nRemove a leaf at the given position\nConvert the given index to a vector of branch indices …\nTrim the leaf at position <code>pos</code> from memory.\nReturns the leaf value given a position\nImplementation of a typical Sparse Merkle Tree.\nUpdate the leaf value at a given position\nApply an update function <code>f</code> at a given position\nVerify an element is a leaf of a Merkle tree given the …\nA standard append only Merkle tree implementation\nReturns the argument unchanged.\nConstruct a new Merkle tree with given height from a data …\nCalls <code>U::from(self)</code>.\nInitialize an empty Merkle tree.\nDigest error, {0}\nMerkle tree is already full.\nQueried leaf is already occupied.\nQueried leaf is forgotten.\nInconsistent Structure error, {0}\nError type for Merkle tree\nQueried leaf isn’t in this Merkle tree\nParameters error, {0}\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nElement type for interval merkle tree\nInterval merkle tree instantiation for interval merkle …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nAssociated type needed to express trait bounds.\nAssociated type needed to express trait bounds.\nLike <code>HasherMerkleTree</code> except with additional parameters.\nConvenience trait and blanket impl for downstream trait …\nA struct that impls <code>DigestAlgorithm</code> for use with <code>MerkleTree</code>…\nMerkle tree generic over <code>Digest</code> hasher <code>H</code>.\nNewtype wrapper for hash output that impls <code>NodeValue</code>.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nA standard append only Merkle tree implementation\nReturns the argument unchanged.\nConstruct a new Merkle tree with given height from a data …\nCalls <code>U::from(self)</code>.\nInitialize an empty Merkle tree.\nAn internal branching node\nAn empty subtree.\nThe subtree is forgotten from the memory\nWrapper for the actual hash function\nMerkle tree using keccak256 hash\nInternal node for merkle tree\nA leaf node\nLight weight merkle tree using Keccak256 hash\nLight weight merkle tree using SHA3 hash\nAn internal Merkle node.\nA (non)membership Merkle proof consists of all values of …\nWrapper for rescue hash function\nA standard light merkle tree using RATE-3 rescue hash …\nA standard merkle tree using RATE-3 rescue hash function\nExample instantiation of a SparseMerkleTree indexed by I\nMerkle tree using SHA3 hash\nWrapper for the actual hash function\nInternal node for merkle tree\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nExpected height of the Merkle tree.\nMacros for implementing ToTreversalPath for BigUint types\nMacros for implementing ToTreversalPath for primitive types\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturn all values of siblings of this Merkle path\nAll it’s children\nAssociated element of this leaf\nIndex of this leaf\nMerkle hash value of this subtree\nMerkle hash value of this leaf\nMerkle hash value of this forgotten subtree\nA standard append only Merkle tree implementation\nReturns the argument unchanged.\nBuild a universal merkle tree from a key-value set.\nCalls <code>U::from(self)</code>.\nInitialize an empty Merkle tree.\nWARN(#495): this method breaks non-membership proofs.")