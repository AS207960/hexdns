#!/usr/bin/env bash

cd hexdns_django || exit
./build.sh || exit
cd ../axfr || exit
./build.sh || exit
cd ../axfr-notify || exit
./build.sh || exit
cd ../dnssec-signer || exit
./build.sh || exit
cd ../knot || exit
./build.sh || exit