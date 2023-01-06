use jf_distributed::worker::run_worker;

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("usage: {} <me>", args[0]);
        return Ok(());
    }

    let me = args[1].parse()?;

    run_worker(me).await
}
