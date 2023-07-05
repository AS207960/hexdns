fn main() {
    tonic_build::configure()
        .build_client(false)
        .build_server(false)
        .compile(
            &["../axfr/src/axfr.proto"],
            &["../axfr/src/"]
        )
        .unwrap();
}