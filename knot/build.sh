#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "as207960/hexdns-knot-sidecar:$VERSION" . || exit
docker push "as207960/hexdns-knot-sidecar:$VERSION"

docker build -t "as207960/hexdns-knot-sidecar-secondary:$VERSION" -f Dockerfile.secondary . || exit
docker push "as207960/hexdns-knot-sidecar-secondary:$VERSION"
