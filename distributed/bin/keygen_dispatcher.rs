use std::{
    fs::{create_dir_all, File},
    io::BufWriter,
};

use ark_serialize::{CanonicalSerialize, Write};
use futures::future::join_all;
use jf_distributed::{
    circuit2::generate_circuit,
    config::NetworkConfig,
    dispatcher::{connect, Plonk, BIN_PATH},
    utils::serialize,
    constants::NUM_WIRE_TYPES
};
use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(BIN_PATH)?;
    let network: NetworkConfig =
        serde_json::from_reader(File::open("config/network.json")?).unwrap();
    assert_eq!(network.workers.len(), NUM_WIRE_TYPES);

    let mut seed = [0; 32];
    thread_rng().fill_bytes(&mut seed);

    let rng = &mut ChaChaRng::from_seed(seed);

    let (srs_size, public_inputs) = {
        let circuit = generate_circuit(rng).unwrap();
        (circuit.srs_size().unwrap(), circuit.public_input().unwrap())
    };
    BufWriter::new(File::create(format!("{}/circuit.inputs", BIN_PATH)).unwrap())
        .write_all(serialize(&public_inputs))
        .unwrap();
    let srs = Plonk::universal_setup(srs_size, rng);

    tokio::task::LocalSet::new()
        .run_until(async {
            let workers = join_all(
                network.workers.iter().map(|addr| async move { connect(addr).await.unwrap() }),
            )
            .await;
            let vk = Plonk::key_gen_async(&workers, seed, srs, public_inputs.len()).await;

            for i in &vk.selector_comms {
                println!("{}", i.0);
            }
            for i in &vk.sigma_comms {
                println!("{}", i.0);
            }

            vk.serialize_unchecked(File::create(format!("{}/vk.bin", BIN_PATH)).unwrap()).unwrap();
        })
        .await;

    Ok(())
}
