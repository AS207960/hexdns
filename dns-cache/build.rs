fn main() {
    tonic_build::compile_protos("src/dns.proto").unwrap();
}