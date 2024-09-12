(function() {var implementors = {
"jf_aead":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_aead/struct.EncKey.html\" title=\"struct jf_aead::EncKey\">EncKey</a>&gt; for [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.array.html\">32</a>]"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.array.html\">32</a>]&gt; for <a class=\"struct\" href=\"jf_aead/struct.EncKey.html\" title=\"struct jf_aead::EncKey\">EncKey</a>"]],
"jf_elgamal":[["impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"jf_elgamal/struct.EncKey.html\" title=\"struct jf_elgamal::EncKey\">EncKey</a>&lt;P&gt;&gt; for (P::BaseField, P::BaseField)<div class=\"where\">where\n    P: Config,</div>"]],
"jf_merkle_tree":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_rescue/enum.RescueError.html\" title=\"enum jf_rescue::RescueError\">RescueError</a>&gt; for <a class=\"enum\" href=\"jf_merkle_tree/errors/enum.MerkleTreeError.html\" title=\"enum jf_merkle_tree::errors::MerkleTreeError\">MerkleTreeError</a>"],["impl&lt;H&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"jf_merkle_tree/hasher/struct.HasherNode.html\" title=\"struct jf_merkle_tree::hasher::HasherNode\">HasherNode</a>&lt;H&gt;&gt; for TaggedBase64<div class=\"where\">where\n    H: Digest,</div>"],["impl&lt;H&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_merkle_tree/hasher/struct.HasherNode.html\" title=\"struct jf_merkle_tree::hasher::HasherNode\">HasherNode</a>&lt;H&gt;&gt; for TaggedBase64<div class=\"where\">where\n    H: Digest,</div>"],["impl&lt;H&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;GenericArray&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.u8.html\">u8</a>, &lt;H as OutputSizeUser&gt;::OutputSize&gt;&gt; for <a class=\"struct\" href=\"jf_merkle_tree/hasher/struct.HasherNode.html\" title=\"struct jf_merkle_tree::hasher::HasherNode\">HasherNode</a>&lt;H&gt;<div class=\"where\">where\n    H: Digest,</div>"]],
"jf_pcs":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_pcs/transcript/enum.TranscriptError.html\" title=\"enum jf_pcs::transcript::TranscriptError\">TranscriptError</a>&gt; for <a class=\"enum\" href=\"jf_pcs/errors/enum.PCSError.html\" title=\"enum jf_pcs::errors::PCSError\">PCSError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SerializationError&gt; for <a class=\"enum\" href=\"jf_pcs/errors/enum.PCSError.html\" title=\"enum jf_pcs::errors::PCSError\">PCSError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SerializationError&gt; for <a class=\"enum\" href=\"jf_pcs/transcript/enum.TranscriptError.html\" title=\"enum jf_pcs::transcript::TranscriptError\">TranscriptError</a>"],["impl&lt;T, E&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;T&gt; for <a class=\"struct\" href=\"jf_pcs/prelude/struct.Commitment.html\" title=\"struct jf_pcs::prelude::Commitment\">Commitment</a>&lt;E&gt;<div class=\"where\">where\n    T: AffineRepr,\n    E: Pairing&lt;G1Affine = T&gt;,</div>"]],
"jf_plonk":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_pcs/errors/enum.PCSError.html\" title=\"enum jf_pcs::errors::PCSError\">PCSError</a>&gt; for <a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>&gt; for <a class=\"enum\" href=\"jf_relation/enum.CircuitError.html\" title=\"enum jf_relation::CircuitError\">CircuitError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_plonk/errors/enum.SnarkError.html\" title=\"enum jf_plonk::errors::SnarkError\">SnarkError</a>&gt; for <a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_relation/enum.CircuitError.html\" title=\"enum jf_relation::CircuitError\">CircuitError</a>&gt; for <a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_rescue/enum.RescueError.html\" title=\"enum jf_rescue::RescueError\">RescueError</a>&gt; for <a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.81.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SerializationError&gt; for <a class=\"enum\" href=\"jf_plonk/errors/enum.PlonkError.html\" title=\"enum jf_plonk::errors::PlonkError\">PlonkError</a>"],["impl&lt;E, F, P1, P2&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.VerifyingKey.html\" title=\"struct jf_plonk::proof_system::structs::VerifyingKey\">VerifyingKey</a>&lt;E&gt;&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.81.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;E::BaseField&gt;<div class=\"where\">where\n    E: Pairing&lt;G1Affine = Affine&lt;P1&gt;, G2Affine = Affine&lt;P2&gt;, TargetField = Fp2&lt;F&gt;&gt;,\n    F: Fp2Config&lt;Fp = E::BaseField&gt;,\n    P1: SWCurveConfig&lt;BaseField = E::BaseField, ScalarField = E::ScalarField&gt;,\n    P2: SWCurveConfig&lt;BaseField = E::TargetField, ScalarField = E::ScalarField&gt;,</div>"],["impl&lt;E, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.Proof.html\" title=\"struct jf_plonk::proof_system::structs::Proof\">Proof</a>&lt;E&gt;&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.81.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;E::BaseField&gt;<div class=\"where\">where\n    E: Pairing&lt;G1Affine = Affine&lt;P&gt;&gt;,\n    P: SWCurveConfig&lt;BaseField = E::BaseField, ScalarField = E::ScalarField&gt;,</div>"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.BatchProof.html\" title=\"struct jf_plonk::proof_system::structs::BatchProof\">BatchProof</a>&lt;E&gt;&gt; for TaggedBase64"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.Proof.html\" title=\"struct jf_plonk::proof_system::structs::Proof\">Proof</a>&lt;E&gt;&gt; for TaggedBase64"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.BatchProof.html\" title=\"struct jf_plonk::proof_system::structs::BatchProof\">BatchProof</a>&lt;E&gt;&gt; for TaggedBase64"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.Proof.html\" title=\"struct jf_plonk::proof_system::structs::Proof\">Proof</a>&lt;E&gt;&gt; for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.BatchProof.html\" title=\"struct jf_plonk::proof_system::structs::BatchProof\">BatchProof</a>&lt;E&gt;"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.Proof.html\" title=\"struct jf_plonk::proof_system::structs::Proof\">Proof</a>&lt;E&gt;&gt; for TaggedBase64"],["impl&lt;F: Field&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.ProofEvaluations.html\" title=\"struct jf_plonk::proof_system::structs::ProofEvaluations\">ProofEvaluations</a>&lt;F&gt;&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.81.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;F&gt;"]],
"jf_relation":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_relation/constraint_system/struct.BoolVar.html\" title=\"struct jf_relation::constraint_system::BoolVar\">BoolVar</a>&gt; for <a class=\"type\" href=\"jf_relation/constraint_system/type.Variable.html\" title=\"type jf_relation::constraint_system::Variable\">Variable</a>"],["impl&lt;F, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;&gt; for Affine&lt;P&gt;<div class=\"where\">where\n    F: PrimeField,\n    P: Config&lt;BaseField = F&gt;,</div>"],["impl&lt;F, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;&gt; for Projective&lt;P&gt;<div class=\"where\">where\n    F: PrimeField,\n    P: Config&lt;BaseField = F&gt;,</div>"],["impl&lt;F, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Affine&lt;P&gt;&gt; for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/emulated/struct.SWPoint.html\" title=\"struct jf_relation::gadgets::ecc::emulated::SWPoint\">SWPoint</a>&lt;F&gt;<div class=\"where\">where\n    F: PrimeField,\n    P: SWCurveConfig&lt;BaseField = F&gt;,</div>"],["impl&lt;F, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Affine&lt;P&gt;&gt; for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;<div class=\"where\">where\n    F: PrimeField + <a class=\"trait\" href=\"jf_relation/gadgets/ecc/trait.SWToTEConParam.html\" title=\"trait jf_relation::gadgets::ecc::SWToTEConParam\">SWToTEConParam</a>,\n    P: SWParam&lt;BaseField = F&gt;,</div>"],["impl&lt;F, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Affine&lt;P&gt;&gt; for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;<div class=\"where\">where\n    F: PrimeField,\n    P: Config&lt;BaseField = F&gt;,</div>"],["impl&lt;F, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Projective&lt;P&gt;&gt; for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;<div class=\"where\">where\n    F: PrimeField,\n    P: Config&lt;BaseField = F&gt;,</div>"]],
"jf_rescue":[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.array.html\">[F; 4]</a>&gt; for <a class=\"struct\" href=\"jf_rescue/struct.RescueVector.html\" title=\"struct jf_rescue::RescueVector\">RescueVector</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.slice.html\">[F]</a>&gt; for <a class=\"struct\" href=\"jf_rescue/struct.RescueVector.html\" title=\"struct jf_rescue::RescueVector\">RescueVector</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"jf_rescue/trait.RescueParameter.html\" title=\"trait jf_rescue::RescueParameter\">RescueParameter</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"jf_rescue/struct.PRP.html\" title=\"struct jf_rescue::PRP\">PRP</a>&lt;F&gt;&gt; for <a class=\"struct\" href=\"jf_rescue/struct.Permutation.html\" title=\"struct jf_rescue::Permutation\">Permutation</a>&lt;F&gt;"],["impl&lt;F: PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;[<a class=\"struct\" href=\"jf_rescue/struct.RescueVector.html\" title=\"struct jf_rescue::RescueVector\">RescueVector</a>&lt;F&gt;; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/std/primitive.array.html\">4</a>]&gt; for <a class=\"struct\" href=\"jf_rescue/struct.RescueMatrix.html\" title=\"struct jf_rescue::RescueMatrix\">RescueMatrix</a>&lt;F&gt;"]],
"jf_signature":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;BLST_ERROR&gt; for <a class=\"enum\" href=\"jf_signature/enum.SignatureError.html\" title=\"enum jf_signature::SignatureError\">SignatureError</a>"]],
"jf_utils":[["impl&lt;T: CanonicalSerialize&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;T&gt; for <a class=\"struct\" href=\"jf_utils/struct.CanonicalBytes.html\" title=\"struct jf_utils::CanonicalBytes\">CanonicalBytes</a>"]],
"jf_vdf":[["impl&lt;F, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;T&gt; for <a class=\"struct\" href=\"jf_vdf/minroot/struct.MinRootElement.html\" title=\"struct jf_vdf::minroot::MinRootElement\">MinRootElement</a>&lt;F&gt;<div class=\"where\">where\n    T: AffineRepr&lt;BaseField = F&gt;,\n    F: <a class=\"trait\" href=\"jf_vdf/minroot/trait.MinRootField.html\" title=\"trait jf_vdf::minroot::MinRootField\">MinRootField</a>,</div>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()