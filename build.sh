#!/usr/bin/env bash

./hexdns_django/build.sh || exit
./axfr/build.sh || exit
./knot/build.sh || exit