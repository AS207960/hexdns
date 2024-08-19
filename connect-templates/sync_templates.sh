#!/usr/bin/env bash

export MC_HOST_garage=https://$S3_ACCESS_KEY_ID:$S3_SECRET_ACCESS_KEY@s3.as207960.net
export DISABLE_PAGER=true
export MC_NO_COLOR=true
git clone https://github.com/Domain-Connect/Templates.git /tmp/templates || exit
mc mirror --overwrite --remove --exclude "README.md" --exclude ".git/*" --exclude ".github/*" /tmp/templates garage/hexdns-connect-templates || exit
rm -rf /tmp/templates || exit