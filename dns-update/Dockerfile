FROM ekidd/rust-musl-builder:nightly-2021-12-23 AS builder

ADD --chown=rust:rust . ./
RUN USER=rust cargo build --release --bin update

FROM scratch

COPY --from=builder --chown=0:0 /etc/ssl/certs /etc/ssl/certs
COPY --from=builder --chown=0:0 /home/rust/src/target/x86_64-unknown-linux-musl/release/update /

ENTRYPOINT ["/update"]
