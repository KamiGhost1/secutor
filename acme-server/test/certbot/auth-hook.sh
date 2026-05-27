#!/usr/bin/env bash
# certbot manual auth-hook. Receives:
#   CERTBOT_DOMAIN     — base domain (e.g. foo.lan)
#   CERTBOT_VALIDATION — TXT value to publish at _acme-challenge.<domain>
# Writes the value to a file that test/certbot/server.ts reads as the
# in-process TXT resolver.

set -e
mkdir -p "$TXT_STORE"
echo "$CERTBOT_VALIDATION" >> "$TXT_STORE/_acme-challenge.${CERTBOT_DOMAIN}.txt"
echo "[auth-hook] published TXT for $CERTBOT_DOMAIN"
