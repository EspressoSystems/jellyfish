use jf_distributed::worker::Worker;

#[tokio::main]
pub async fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 2, "Usage: {} <me>", args[0]);

    let me = args[1].parse().unwrap();

    Worker::new(me).start().await.unwrap();
}
