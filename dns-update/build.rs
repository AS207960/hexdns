fn main() {
    tonic_prost_build::compile_protos("src/dns.proto").unwrap();
}