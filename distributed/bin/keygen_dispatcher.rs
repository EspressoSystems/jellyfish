use std::fs::{create_dir_all, File};

use ark_serialize::CanonicalSerialize;
use futures::future::join_all;
use jf_distributed::{
    circuit::generate_circuit,
    config::{DATA_DIR, WORKERS},
    dispatcher::Plonk,
    storage::SliceStorage,
};
use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use stubborn_io::StubbornTcpStream;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(DATA_DIR.join("dispatcher"))?;

    let mut seed = [0; 32];
    thread_rng().fill_bytes(&mut seed);

    let rng = &mut ChaChaRng::from_seed(seed);

    let (srs_size, public_inputs) = {
        let circuit = generate_circuit(rng).unwrap();
        (circuit.srs_size().unwrap(), circuit.public_input().unwrap())
    };
    SliceStorage::new(DATA_DIR.join("dispatcher/circuit.inputs.bin")).store(&public_inputs)?;

    let srs = Plonk::universal_setup(srs_size, rng);

    let mut workers = join_all(WORKERS.iter().map(|worker| async move {
        let stream = StubbornTcpStream::connect(worker).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }))
    .await;
    let vk = Plonk::key_gen_async(&mut workers, seed, srs, public_inputs.len()).await;

    for i in &vk.selector_comms {
        println!("{}", i.0);
    }
    for i in &vk.sigma_comms {
        println!("{}", i.0);
    }

    vk.serialize_unchecked(File::create(DATA_DIR.join("dispatcher/vk.bin"))?)?;
    Ok(())
}
