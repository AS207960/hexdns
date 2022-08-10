#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker buildx build --platform linux/amd64 --push -t "as207960/hexdns-knot-sidecar:$VERSION" . || exit
docker buildx build --platform linux/amd64 --push -t "as207960/hexdns-knot-sidecar-secondary:$VERSION" -f Dockerfile.secondary . || exit
