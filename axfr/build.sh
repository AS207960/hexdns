#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker buildx build --platform linux/amd64 --push -t "as207960/hexdns-axfr:$VERSION" . || exit
