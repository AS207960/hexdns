#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

sed -e "s/(version)/$VERSION/g" < django.yaml | kubectl apply -f - || exit
kubectl apply -f nginx.yaml || exit
kubectl apply -f redis.yaml || exit

sentry-cli releases --org we-will-fix-your-pc deploys $VERSION new -e prod