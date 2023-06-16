fn main() {
    tonic_build::compile_protos("src/axfr.proto").unwrap();
}