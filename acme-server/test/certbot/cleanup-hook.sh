#!/usr/bin/env bash
set -e
rm -f "$TXT_STORE/_acme-challenge.${CERTBOT_DOMAIN}.txt"
echo "[cleanup-hook] removed TXT for $CERTBOT_DOMAIN"
