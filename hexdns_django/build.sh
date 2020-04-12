#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "as207960/hexdns-django:$VERSION" . || exit
docker push "as207960/hexdns-django:$VERSION" || exit

sentry-cli releases --org as207960 new -p hexdns "$VERSION" || exit
sentry-cli releases --org as207960 set-commits --auto "$VERSION"
