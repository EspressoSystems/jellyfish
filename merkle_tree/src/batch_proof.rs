use crate::{MerkleTreeError, MerkleTreeProof, NodeValue};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tagged::Tagged;

/// A compact batch proof for multiple elements in a Merkle tree.
/// Optimizes proof size through:
/// 1. Identifying and storing shared nodes between proofs
/// 2. Storing only differing nodes for individual proofs
/// 3. Efficient node reuse during verification
///
/// # Example
/// ```ignore
/// let proofs = vec![proof1, proof2, proof3];
/// let batch_proof = CompactBatchProof::new(proofs)?;
/// 
/// // Verify all proofs
/// tree.batch_verify(positions, elements, &batch_proof)?;
/// ```
#[derive(Clone, Debug, Hash, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[tagged("COMPACT_BATCH_PROOF")]
pub struct CompactBatchProof<T: NodeValue> {
    /// Shared nodes at each tree level that are common across multiple proofs.
    /// Vector index corresponds to the tree level.
    shared_nodes: Vec<Vec<T>>,
    
    /// Individual nodes for each proof.
    /// Contains only nodes that differ from shared nodes.
    /// Structure: [proof][level][nodes at level]
    individual_proofs: Vec<Vec<Vec<T>>>,

    /// Height of the Merkle tree
    height: usize,
}

impl<T: NodeValue> CompactBatchProof<T> {
    /// Creates a new compact batch proof from a set of individual proofs.
    ///
    /// # Arguments
    /// * `proofs` - Vector of individual MerkleTreeProof instances
    ///
    /// # Errors
    /// * `ParametersError` - if input proofs are empty or have inconsistent heights
    ///
    /// # Example
    /// ```ignore
    /// let proofs = vec![proof1, proof2, proof3];
    /// let batch_proof = CompactBatchProof::new(proofs)?;
    /// ```
    pub fn new(proofs: Vec<MerkleTreeProof<T>>) -> Result<Self, MerkleTreeError> {
        // Check for empty vector
        if proofs.is_empty() {
            return Err(MerkleTreeError::ParametersError(
                "Empty proofs vector".to_string(),
            ));
        }

        let height = proofs[0].height();
        
        // Check height consistency
        if proofs.iter().any(|p| p.height() != height) {
            return Err(MerkleTreeError::ParametersError(
                "Inconsistent proof heights".to_string(),
            ));
        }

        let mut shared = vec![vec![]; height];
        let mut individual = Vec::with_capacity(proofs.len());
        
        // Convert proofs to the required format
        let proof_values: Vec<Vec<Vec<T>>> = proofs.iter()
            .map(|p| p.path_values().to_vec())
            .collect();

        // Find shared nodes at each level
        for level in 0..height {
            let mut level_nodes = proof_values[0][level].clone();
            
            // Compare nodes from all proofs at current level
            for proof in proof_values.iter().skip(1) {
                for (idx, node) in proof[level].iter().enumerate() {
                    if level_nodes[idx] != *node {
                        level_nodes[idx] = T::default();
                    }
                }
            }
            shared[level] = level_nodes;
        }
        
        // Create individual proofs with only differing nodes
        for proof in proof_values {
            let mut indiv = Vec::with_capacity(height);
            for (level, nodes) in proof.iter().enumerate() {
                let mut level_nodes = vec![T::default(); nodes.len()];
                for (idx, node) in nodes.iter().enumerate() {
                    if *node != shared[level][idx] {
                        level_nodes[idx] = *node;
                    }
                }
                indiv.push(level_nodes);
            }
            individual.push(indiv);
        }
        
        Ok(Self {
            shared_nodes: shared,
            individual_proofs: individual,
            height,
        })
    }
    
    /// Returns shared nodes common to all proofs
    pub fn get_shared_nodes(&self) -> &[Vec<T>] {
        &self.shared_nodes
    }
    
    /// Returns individual parts of the proofs
    pub fn get_individual_proofs(&self) -> &[Vec<Vec<T>>] {
        &self.individual_proofs
    }

    /// Returns the height of the Merkle tree
    pub fn height(&self) -> usize {
        self.height
    }

    /// Reconstructs a complete proof for a specific index
    ///
    /// # Arguments
    /// * `proof_idx` - Index of the proof in the batch
    ///
    /// # Errors
    /// * `ParametersError` - if index is out of bounds
    pub fn get_proof(&self, proof_idx: usize) -> Result<MerkleTreeProof<T>, MerkleTreeError> {
        if proof_idx >= self.individual_proofs.len() {
            return Err(MerkleTreeError::ParametersError(
                "Proof index out of bounds".to_string(),
            ));
        }

        let mut proof_path = Vec::with_capacity(self.height);
        
        for level in 0..self.height {
            let mut level_nodes = self.shared_nodes[level].clone();
            let indiv_nodes = &self.individual_proofs[proof_idx][level];
            
            for (idx, node) in indiv_nodes.iter().enumerate() {
                if !node.is_empty() {
                    level_nodes[idx] = *node;
                }
            }
            proof_path.push(level_nodes);
        }

        Ok(MerkleTreeProof(proof_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed25519::Fr;

    fn create_test_proof(height: usize, value: u8) -> MerkleTreeProof<Fr> {
        let nodes = (0..height)
            .map(|_| vec![Fr::from(value as u64); 2])
            .collect();
        MerkleTreeProof(nodes)
    }

    #[test]
    fn test_new_batch_proof() {
        let proofs = vec![
            create_test_proof(3, 1),
            create_test_proof(3, 2),
            create_test_proof(3, 1),
        ];

        let batch_proof = CompactBatchProof::new(proofs).unwrap();
        assert_eq!(batch_proof.height(), 3);
        assert_eq!(batch_proof.get_shared_nodes().len(), 3);
        assert_eq!(batch_proof.get_individual_proofs().len(), 3);
    }

    #[test]
    fn test_empty_proofs() {
        let proofs: Vec<MerkleTreeProof<Fr>> = vec![];
        assert!(CompactBatchProof::new(proofs).is_err());
    }

    #[test]
    fn test_inconsistent_heights() {
        let proofs = vec![
            create_test_proof(3, 1),
            create_test_proof(2, 2),
        ];
        assert!(CompactBatchProof::new(proofs).is_err());
    }

    #[test]
    fn test_get_proof() {
        let proofs = vec![
            create_test_proof(3, 1),
            create_test_proof(3, 2),
            create_test_proof(3, 1),
        ];

        let batch_proof = CompactBatchProof::new(proofs.clone()).unwrap();
        
        // Test that we can recover original proofs
        let recovered = batch_proof.get_proof(0).unwrap();
        assert_eq!(recovered, proofs[0]);

        let recovered = batch_proof.get_proof(1).unwrap();
        assert_eq!(recovered, proofs[1]);

        // Test error on invalid index
        assert!(batch_proof.get_proof(5).is_err());
    }

    #[test]
    fn test_compression_efficiency() {
        let proofs = vec![
            create_test_proof(3, 1),
            create_test_proof(3, 1), // Identical proof
            create_test_proof(3, 2),
        ];

        let batch_proof = CompactBatchProof::new(proofs).unwrap();
        
        // Check that identical proofs don't duplicate nodes
        let individual = batch_proof.get_individual_proofs();
        assert!(individual[0].iter().all(|level| level.iter().all(|node| node.is_empty())));
        assert!(individual[1].iter().all(|level| level.iter().all(|node| node.is_empty())));
    }
} 
