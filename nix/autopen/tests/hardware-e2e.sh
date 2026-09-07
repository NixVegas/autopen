#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Morgan Jones
#
# SPDX-License-Identifier: BlueOak-1.0.0
#
# End-to-end proof of the PKCS#11 hardware signing path WITHOUT the client shim:
# a plain autopen `Remote` key drives a signature through the capability socket ->
# HardwareSigner -> a PKCS#11 token, and the signature verifies.
#
# Uses kryoptic as a software token stand-in for the YubiHSM (the backend is
# PKCS#11-agnostic, so this is a config-only swap in production).
#
# Run from the repo root inside the devshell:
#   nix develop -c bash nix/autopen/tests/hardware-e2e.sh
# Optionally pass the PKCS#11 module path as $1 (defaults to nixpkgs#kryoptic).

set -euo pipefail

mod="${1:-$(nix build --no-link --print-out-paths nixpkgs#kryoptic)/lib/libkryoptic_pkcs11.so}"
work="$(mktemp -d)"
cleanup() {
  [[ -n ${srv:-} ]] && kill "${srv}" 2>/dev/null || true
  rm -rf "${work}"
}
trap cleanup EXIT

# A kryoptic token backed by a throwaway sqlite DB.
export KRYOPTIC_CONF="${work}/token.conf"
cat >"${KRYOPTIC_CONF}" <<EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "${work}/token.sql"
EOF

# Initialise the token and generate an RSA-3072 signing key (id 01).
pkcs11-tool --module "${mod}" --init-token --label test --so-pin 0000 >/dev/null 2>&1
pkcs11-tool --module "${mod}" --init-pin --so-pin 0000 --login --pin 1234 >/dev/null 2>&1
pkcs11-tool --module "${mod}" --login --pin 1234 \
  --keypairgen --key-type rsa:3072 --id 01 --label test >/dev/null 2>&1

printf 1234 >"${work}/pin"
uri="pkcs11:token=test;id=%01;type=private;module-path=${mod};pin-source=file:${work}/pin"

# Build once; use the debug binary directly.
cargo build -q
bin="$(cargo metadata --format-version 1 --no-deps 2>/dev/null |
  grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)/debug/autopen"
bin="${bin:-target/debug/autopen}"

mkdir -p "${work}/handle"
sock="${work}/socket"

# Export the public verification key (private key never leaves the token).
"${bin}" signing-key hardware get-verification-key --pkcs11-uri "${uri}" --output "${work}/vk.autopen"

# Serve the token key bound to the file-ref handle.
"${bin}" serve --socket-path "${sock}" --hardware-key "${uri}" "${work}/handle" 2>/dev/null &
srv=$!
for _ in $(seq 1 50); do
  [[ -S ${sock} ]] && break
  sleep 0.1
done

# The "build" creates a plain Remote key (RemoteRef + verification key only).
"${bin}" signing-key remote create --socket-path "${sock}" --file-ref-path "${work}/handle" \
  --verification-key "${work}/vk.autopen" --output "${work}/remote.autopen"

# Sign through the capability socket -> HardwareSigner -> token, then verify.
printf "hello from apk signing" >"${work}/msg"
"${bin}" sign --signing-key "${work}/remote.autopen" --output "${work}/sig" "${work}/msg"
"${bin}" verify --verification-key "${work}/vk.autopen" --signature "${work}/sig" "${work}/msg"

# The Remote key must not leak the module path, PIN, or token label.
if grep -aqE "module-path|pin-source|/nix/store|libkryoptic|token=" "${work}/remote.autopen"; then
  echo "FAIL: Remote key file contains sensitive PKCS#11 details" >&2
  exit 1
fi

echo "OK: hardware signing end-to-end (Remote -> socket -> HardwareSigner -> token) verified"
