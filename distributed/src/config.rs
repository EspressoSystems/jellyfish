use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use once_cell::sync::Lazy;
use serde::Deserialize;

pub const NUM_WIRE_TYPES: usize = 5;

#[derive(Clone, Deserialize)]
pub struct NetworkConfig {
    pub workers: Vec<SocketAddr>,
    pub dispatcher: IpAddr,
}

#[derive(Clone, Deserialize)]
pub struct GpuConfig {
    pub excluded_ids: Vec<usize>,
}

#[derive(Clone, Deserialize)]
pub struct CircuitConfig {
    pub tree_height: u8,
    pub num_membership_proofs: usize,
}

pub static DATA_DIR: Lazy<PathBuf> =
    Lazy::new(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("data"));

pub static CONFIG_DIR: Lazy<PathBuf> =
    Lazy::new(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("config"));

pub static NETWOKR_CONFIG: Lazy<NetworkConfig> = Lazy::new(|| {
    let mut bytes = vec![];
    File::open(CONFIG_DIR.join("network.toml")).unwrap().read_to_end(&mut bytes).unwrap();
    toml::from_slice(&bytes).unwrap()
});

pub static GPU_CONFIG: Lazy<GpuConfig> = Lazy::new(|| {
    let mut bytes = vec![];
    File::open(CONFIG_DIR.join("gpu.toml")).unwrap().read_to_end(&mut bytes).unwrap();
    toml::from_slice(&bytes).unwrap()
});

pub static CIRCUIT_CONFIG: Lazy<CircuitConfig> = Lazy::new(|| {
    let mut bytes = vec![];
    File::open(CONFIG_DIR.join("circuit.toml")).unwrap().read_to_end(&mut bytes).unwrap();
    toml::from_slice(&bytes).unwrap()
});

pub static WORKERS: Lazy<&'static [SocketAddr]> = Lazy::new(|| &NETWOKR_CONFIG.workers);

pub static IP_NAME_MAP: Lazy<HashMap<IpAddr, String>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(NETWOKR_CONFIG.dispatcher, "Dispatcher".to_string());
    for (i, addr) in NETWOKR_CONFIG.workers.iter().enumerate() {
        map.insert(addr.ip(), format!("Worker{}", i));
    }
    map
});
