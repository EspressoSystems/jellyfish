use std::{fs::File, time::Instant};

use ark_serialize::CanonicalDeserialize;
use futures::future::join_all;
use jf_distributed::{
    config::{DATA_DIR, WORKERS},
    dispatcher::Plonk,
    storage::SliceStorage,
};
use jf_plonk::{
    prelude::VerifyingKey,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use stubborn_io::StubbornTcpStream;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vk = VerifyingKey::deserialize_unchecked(File::open(DATA_DIR.join("dispatcher/vk.bin"))?)?;
    let public_inputs = SliceStorage::new(DATA_DIR.join("dispatcher/circuit.inputs.bin")).load()?;

    let mut workers = join_all(WORKERS.iter().map(|worker| async move {
        let stream = StubbornTcpStream::connect(worker).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }))
    .await;
    for i in 0..10 {
        let now = Instant::now();
        let proof = Plonk::prove_async(&mut workers, &public_inputs, &vk).await.unwrap();
        println!("prove {}: {:?}", i, now.elapsed());
        assert!(PlonkKzgSnark::verify::<StandardTranscript>(&vk, &public_inputs, &proof).is_ok());
    }
    Ok(())
}
