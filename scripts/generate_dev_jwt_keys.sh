#!/bin/bash
# Generates a local-dev-only RSA keypair for signing JWTs and writes it,
# base64-encoded, into a root .env file that docker-compose automatically
# loads for variable substitution. The .env file is git-ignored — this
# script is how you (re)produce your own local keypair; nothing resembling
# a real secret is ever committed. In Week 2 this is replaced by a key
# managed in AWS Secrets Manager with a documented rotation procedure
# (tracked under OBJ-03 / V-CLD-04).
#
# Usage: ./scripts/generate_dev_jwt_keys.sh
set -euo pipefail

cd "$(dirname "$0")/.."

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

openssl genrsa -out "$TMP_DIR/jwt_private.pem" 2048 2>/dev/null
openssl rsa -in "$TMP_DIR/jwt_private.pem" -pubout -out "$TMP_DIR/jwt_public.pem" 2>/dev/null

PRIVATE_B64=$(base64 -w0 "$TMP_DIR/jwt_private.pem")
PUBLIC_B64=$(base64 -w0 "$TMP_DIR/jwt_public.pem")

# Remove any previous JWT_* lines, then append the fresh pair.
if [ -f .env ]; then
    grep -v -E '^JWT_(PRIVATE|PUBLIC)_KEY_B64=' .env > "$TMP_DIR/env.filtered" || true
    mv "$TMP_DIR/env.filtered" .env
else
    touch .env
fi

{
    echo "JWT_PRIVATE_KEY_B64=$PRIVATE_B64"
    echo "JWT_PUBLIC_KEY_B64=$PUBLIC_B64"
} >> .env

echo "Wrote a fresh dev-only RSA keypair to .env (JWT_PRIVATE_KEY_B64, JWT_PUBLIC_KEY_B64)."
echo "Restart the stack to pick it up: docker compose up -d --build"
