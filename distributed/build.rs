fn main() {
    ::capnpc::CompilerCommand::new().file("protocol/plonk.capnp").run().unwrap();
}