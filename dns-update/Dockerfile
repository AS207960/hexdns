FROM ubuntu:22.04 AS builder
ARG TOOLCHAIN=stable

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -yq curl zip build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    useradd rust --user-group --create-home --shell /bin/bash --groups sudo

ENV RUSTUP_HOME=/opt/rust/rustup \
    PATH=/home/rust/.cargo/bin:/opt/rust/cargo/bin:/usr/local/musl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN curl https://sh.rustup.rs -sSf | \
    env CARGO_HOME=/opt/rust/cargo \
        sh -s -- -y --default-toolchain $TOOLCHAIN --profile minimal --no-modify-path && \
    env CARGO_HOME=/opt/rust/cargo \
        rustup component add rustfmt && \
    env CARGO_HOME=/opt/rust/cargo \
        rustup component add clippy && \
    env CARGO_HOME=/opt/rust/cargo \
        rustup target add x86_64-unknown-linux-musl
ADD cargo-config.toml /opt/rust/cargo/config

ENV X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/usr/local/musl/ \
    X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1 \
    PQ_LIB_STATIC_X86_64_UNKNOWN_LINUX_MUSL=1 \
    PG_CONFIG_X86_64_UNKNOWN_LINUX_GNU=/usr/bin/pg_config \
    PKG_CONFIG_ALLOW_CROSS=true \
    PKG_CONFIG_ALL_STATIC=true \
    LIBZ_SYS_STATIC=1 \
    TARGET=musl \
    AR=ar

USER rust
RUN mkdir -p /home/rust/libs /home/rust/src /home/rust/.cargo && \
    ln -s /opt/rust/cargo/config /home/rust/.cargo/config

WORKDIR /home/rust/src

RUN curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v23.3/protoc-23.3-linux-x86_64.zip && \
  mkdir -p ~/.local && \
  unzip protoc-23.3-linux-x86_64.zip -d ~/.local && \
  rm protoc-23.3-linux-x86_64.zip && \
  chmod +x ~/.local/bin/protoc

ENV PROTOC=/home/rust/.local/bin/protoc

ADD --chown=rust:rust . ./
RUN USER=rust cargo build --release

FROM scratch

COPY --from=builder --chown=0:0 /home/rust/src/target/x86_64-unknown-linux-musl/release/update /

ENTRYPOINT ["/update"]
