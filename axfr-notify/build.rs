fn main() {
    tonic_build::configure()
        .build_client(false)
        .build_server(false)
        .compile(
            &["src/axfr.proto"],
            &["src/"]
        )
        .unwrap();
}