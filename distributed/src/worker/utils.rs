use std::net::SocketAddr;

use ark_bls12_381::{Fr, G1Projective};
use fn_timer::fn_timer;
use futures::future::join_all;
use stubborn_io::StubbornTcpStream;

use super::PlonkImplInner;
use crate::{config::WORKERS, gpu::MSM, mmap::Mmap, storage::SliceStorage};

impl PlonkImplInner {
    #[fn_timer(format!("vec_to_mmap {name}"))]
    pub fn vec_to_mmap<T>(&self, name: &str, mut data: Vec<T>) -> Mmap<T> {
        let mmap = SliceStorage::new(self.data_path.join(format!("{name}.bin"))).store_and_mmap(&data).unwrap();
        data.clear();
        data.shrink_to_fit();
        mmap
    }

    #[fn_timer(format!("slice_to_mmap {name}"))]
    pub fn slice_to_mmap<T>(&self, name: &str, data: &[T]) -> Mmap<T> {
        SliceStorage::new(self.data_path.join(format!("{name}.bin"))).store_and_mmap(data).unwrap()
    }
}

impl PlonkImplInner {
    pub async fn peer(id: usize) -> StubbornTcpStream<&'static SocketAddr> {
        let stream = StubbornTcpStream::connect(&WORKERS[id]).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }

    pub async fn peers() -> Vec<StubbornTcpStream<&'static SocketAddr>> {
        join_all(WORKERS.iter().map(|worker| async move {
            let stream = StubbornTcpStream::connect(worker).await.unwrap();
            stream.set_nodelay(true).unwrap();
            stream
        }))
        .await
    }
}

impl PlonkImplInner {
    #[fn_timer]
    #[inline]
    pub fn commit_polynomial(&self, poly: &[Fr]) -> G1Projective {
        self.ck.mmap().unwrap().var_msm(poly)
    }
}
