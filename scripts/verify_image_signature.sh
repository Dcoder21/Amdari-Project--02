#!/bin/bash
# Fix for V-PIP-01: verifies the given image's cosign (keyless) signature
# and fails closed — a non-zero exit here must block whatever called this
# script (the verify-signature CI job, and the deploy job before it force-
# deploys to ECS) from trusting the image.
#
# Usage: scripts/verify_image_signature.sh <image-ref>
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <image-ref>" >&2
    exit 1
fi

IMAGE_REF="$1"

# Keyless verification trusts the signature only if it was issued by this
# repository's own GitHub Actions workflow (the OIDC identity cosign sign
# used in build-and-push), not any Sigstore-signed image from anywhere.
cosign verify \
    --certificate-identity-regexp "^https://github.com/.+/\.github/workflows/ci\.yml@.+$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$IMAGE_REF"
