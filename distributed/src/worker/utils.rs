use ark_bls12_381::{Fr, G1Projective};
use fn_timer::fn_timer;
use futures::future::join_all;

use super::{connect, PlonkImplInner, WORKERS};
use crate::{
    gpu::MSM,
    utils::{Mmap, MmapConfig},
};

impl PlonkImplInner {
    #[fn_timer(format!("vec_to_mmap {name}"))]
    pub fn vec_to_mmap<T>(&self, name: &str, mut data: Vec<T>) -> Mmap<T> {
        let config = MmapConfig::new(format!("{}/{}.bin", self.bin_path, name));
        config.store(&data).unwrap();
        data.clear();
        data.shrink_to_fit();
        config.load().unwrap()
    }

    #[fn_timer(format!("slice_to_mmap {name}"))]
    pub fn slice_to_mmap<T>(&self, name: &str, data: &[T]) -> Mmap<T> {
        let config = MmapConfig::new(format!("{}/{}.bin", self.bin_path, name));
        config.store(data).unwrap();
        config.load().unwrap()
    }
}

impl PlonkImplInner {
    pub async fn connect_all(&self) {
        let mut this = unsafe { &mut *(self as *const _ as *mut Self) };
        this.connections = join_all(
            WORKERS.iter().map(|worker| async move { connect(worker).await.unwrap() }),
        )
        .await;
    }
}

impl PlonkImplInner {
    #[fn_timer]
    #[inline]
    pub fn commit_polynomial(&self, poly: &[Fr]) -> G1Projective {
        self.ck.load().unwrap().var_msm(poly)
    }
}
