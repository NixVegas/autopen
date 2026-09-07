#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Morgan Jones
#
# SPDX-License-Identifier: BlueOak-1.0.0
#
# T1 vertical slice: apksigner (Java SunPKCS11) -> the autopen PKCS#11 shim ->
# autopen serve -> a PKCS#11 token, producing a valid APK v2/v3 signature.
#
# Uses kryoptic as a software token stand-in for the YubiHSM. Run from the repo
# root inside the devshell (pkcs11-tool + openssl); resolves the JDK/apksigner/
# kryoptic via `nix build`:
#   nix develop -c bash nix/autopen/tests/apk-e2e.sh
#
# SunPKCS11 notes (the T1 findings):
#  - apksigner's bundled JRE is a *minimal* JRE without jdk.crypto.cryptoki;
#    run apksigner's inner script with a full JDK (JAVA_HOME) instead.
#  - Configure SunPKCS11 by name (not --ks-provider-class, which uses the removed
#    JDK-8 SunPKCS11(String) constructor): merge a java.security that sets
#    `security.provider.12=SunPKCS11 <cfg>`, then --ks-provider-name SunPKCS11-<name>.
#  - The proxy private key must expose the standard key-metadata booleans
#    (CKA_SENSITIVE/EXTRACTABLE/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE), which
#    SunPKCS11 reads in one C_GetAttributeValue batch.

set -uo pipefail
cd "$(dirname "$0")/../../.." || exit 1 # repo root
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

work=$(mktemp -d)
mod=$(nix build --no-link --print-out-paths nixpkgs#kryoptic)/lib/libkryoptic_pkcs11.so
fulljdk=$(nix build --no-link --print-out-paths nixpkgs#jdk)
aps=$(nix build --no-link --print-out-paths nixpkgs#apksigner)
inner="${aps}/opt/apksigner/bin/apksigner"

export KRYOPTIC_CONF="${work}/token.conf"
printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s/token.sql"\n' "${work}" >"${KRYOPTIC_CONF}"

# A key + matching self-signed cert; import the key into the token (sign usage).
openssl req -x509 -newkey rsa:3072 -keyout "${work}/key.pem" -out "${work}/cert.pem" \
  -days 3650 -nodes -subj "/CN=autopen-dev" >/dev/null 2>&1
openssl pkcs8 -topk8 -nocrypt -in "${work}/key.pem" -outform DER -out "${work}/key.p8.der"
openssl rsa -in "${work}/key.pem" -pubout -outform DER -out "${work}/pub.der" 2>/dev/null
pkcs11-tool --module "${mod}" --init-token --label test --so-pin 0000 >/dev/null 2>&1
pkcs11-tool --module "${mod}" --init-pin --so-pin 0000 --login --pin 1234 >/dev/null 2>&1
pkcs11-tool --module "${mod}" --login --pin 1234 --write-object "${work}/key.p8.der" \
  --type privkey --id 01 --label apk --usage-sign >/dev/null 2>&1
pkcs11-tool --module "${mod}" --login --pin 1234 --write-object "${work}/pub.der" \
  --type pubkey --id 01 --label apk >/dev/null 2>&1

printf 1234 >"${work}/pin"
uri="pkcs11:token=test;id=%01;type=private;module-path=${mod};pin-source=file:${work}/pin"
bin=target/debug/autopen
mkdir -p "${work}/handle"
sock="${work}/socket"
"${bin}" signing-key hardware get-verification-key --pkcs11-uri "${uri}" --output "${work}/vk.autopen"
"${bin}" serve --socket-path "${sock}" --hardware-key "${uri}" "${work}/handle" 2>/dev/null &
srv=$!
trap 'kill "${srv}" 2>/dev/null; rm -rf "${work}"' EXIT
for _ in $(seq 1 50); do
  [[ -S ${sock} ]] && break
  sleep 0.1
done
"${bin}" signing-key remote create --socket-path "${sock}" --file-ref-path "${work}/handle" \
  --verification-key "${work}/vk.autopen" --output "${work}/remote.autopen"

# A minimal APK (a zip; jar from the JDK avoids a separate zip dependency).
printf '<?xml version="1.0"?><manifest/>' >"${work}/AndroidManifest.xml"
(cd "${work}" && "${fulljdk}/bin/jar" --create --file app.apk AndroidManifest.xml)

# SunPKCS11 config + a merged java.security registering it by name.
so="$(pwd)/target/debug/libautopen_pkcs11.so"
printf 'name = autopen\nlibrary = %s\nslotListIndex = 0\n' "${so}" >"${work}/sunpkcs11.cfg"
printf 'security.provider.12=SunPKCS11 %s\n' "${work}/sunpkcs11.cfg" >"${work}/java.security"

export AUTOPEN_CERT="${work}/cert.pem" AUTOPEN_REMOTE_KEY="${work}/remote.autopen" AUTOPEN_LABEL=apk
JAVA_HOME="${fulljdk}" _JAVA_OPTIONS="-Djava.security.properties=${work}/java.security" \
  "${inner}" sign --ks NONE --ks-type PKCS11 --ks-provider-name SunPKCS11-autopen \
  --ks-key-alias apk --ks-pass pass:0000 --min-sdk-version 24 \
  --out "${work}/app-signed.apk" "${work}/app.apk" 2>/dev/null ||
  fail "apksigner sign failed"

out=$(JAVA_HOME="${fulljdk}" "${inner}" verify --min-sdk-version 24 --verbose "${work}/app-signed.apk" 2>/dev/null) ||
  fail "apksigner verify failed"
echo "${out}" | grep -q "Verified using v2 scheme (APK Signature Scheme v2): true" ||
  fail "v2 signature did not verify"
echo "${out}" | grep -q "Verified using v3 scheme (APK Signature Scheme v3): true" ||
  fail "v3 signature did not verify"

echo "OK: apksigner -> shim -> autopen -> token; APK v2+v3 signatures verify"
