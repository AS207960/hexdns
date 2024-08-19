FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y curl git && \
    curl https://dl.min.io/client/mc/release/linux-amd64/mc \
      --create-dirs \
      -o /usr/local/bin/mc && \
    chmod +x /usr/local/bin/mc && \
    rm -rf /var/lib/apt/lists/*

COPY sync_templates.sh /sync_templates.sh

CMD ["/sync_templates.sh"]