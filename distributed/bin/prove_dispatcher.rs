use std::{
    fs::{create_dir_all, File},
    io::BufReader,
};

use ark_serialize::{CanonicalDeserialize, Read};
use futures::future::join_all;
use jf_distributed::{
    config::NetworkConfig,
    dispatcher::{connect, Plonk, BIN_PATH},
    utils::deserialize, constants::NUM_WIRE_TYPES,
};
use jf_plonk::{
    prelude::VerifyingKey,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(BIN_PATH)?;
    let network: NetworkConfig =
        serde_json::from_reader(File::open("config/network.json")?).unwrap();
    assert_eq!(network.workers.len(), NUM_WIRE_TYPES);

    let vk = VerifyingKey::deserialize_unchecked(File::open(format!("{}/vk.bin", BIN_PATH))?)?;
    let mut public_inputs = vec![];
    BufReader::new(File::open(format!("{}/circuit.inputs", BIN_PATH))?)
        .read_to_end(&mut public_inputs)?;
    let public_inputs = deserialize(&public_inputs);

    tokio::task::LocalSet::new()
        .run_until(async {
            let workers = join_all(
                network.workers.iter().map(|addr| async move { connect(addr).await.unwrap() }),
            )
            .await;
            join_all(
                workers.iter().map(|worker| async move {
                    worker.prove_init_request().send().promise.await.unwrap()
                }),
            )
            .await;
            for _ in 0..10 {
                let proof = Plonk::prove_async(&workers, public_inputs, &vk).await.unwrap();
                assert!(
                    PlonkKzgSnark::verify::<StandardTranscript>(&vk, public_inputs, &proof).is_ok()
                );
            }
        })
        .await;

    Ok(())
}
