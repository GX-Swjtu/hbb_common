fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("protos");
    std::fs::create_dir_all(&out)?;
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out)
        .inputs(["../protos/rendezvous.proto"])
        .include("../protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()?;
    println!("cargo:rerun-if-changed=../protos/rendezvous.proto");
    Ok(())
}
