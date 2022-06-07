use jf_plonk::prelude::*;

fn main() {
    let mut rng = rand::thread_rng();
    let circuit = jf_zprice::generate_circuit(&mut rng).unwrap();
    let max_degree = circuit.srs_size().unwrap();

    // store SRS
    jf_zprice::store_srs(max_degree, None);

    // store proving key and verification key
    let srs = jf_zprice::load_srs(None);
    jf_zprice::store_proving_and_verification_key(srs, None, None);

    // just making sure they can be loaded
    jf_zprice::load_proving_key(None);
    jf_zprice::load_verification_key(None);
}
