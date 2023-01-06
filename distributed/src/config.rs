use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Clone, Deserialize, Default)]
pub struct NetworkConfig {
    pub workers: Vec<SocketAddr>,
}

#[derive(Clone, Deserialize, Default)]
pub struct GpuConfig {
    // TODO: rename to excluded_ids
    pub disabled_ids: Vec<usize>,
}