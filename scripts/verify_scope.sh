#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT}/scope/scope_manifest.yml"
SIG="${MANIFEST}.sig"
KEYRING="${ROOT}/scope/approved_signers.gpg"

if [[ ! -f "${MANIFEST}" ]]; then
  echo "scope_manifest.yml not found at ${MANIFEST}" >&2
  exit 1
fi
if [[ ! -f "${SIG}" ]]; then
  echo "Signature not found at ${SIG}" >&2
  exit 1
fi
if [[ ! -f "${KEYRING}" ]]; then
  echo "approved_signers.gpg not found at ${KEYRING}" >&2
  exit 1
fi

gpg --no-default-keyring --keyring "${KEYRING}" --verify "${SIG}" "${MANIFEST}"
echo "Verified signature for ${MANIFEST}"
