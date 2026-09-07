# SPDX-FileCopyrightText: 2026 Morgan Jones
#
# SPDX-License-Identifier: BlueOak-1.0.0

{
  lib,
  runCommand,
  jdk,
  apksigner,
  autopen,
}:

let
  inherit (autopen.lib.internal) hideDerivation;

  # apksigner's bundled JRE is minimal (no jdk.crypto.cryptoki); run its inner
  # script with a full JDK instead.
  inner = "${apksigner}/opt/apksigner/bin/apksigner";
  shim = "${autopen}/lib/libautopen_pkcs11.so";
in

/**
  Re-sign an APK with a PKCS#11 token key brokered through `autopen`.

  Runs `apksigner` via Java's SunPKCS11, driving the autopen PKCS#11 shim, which
  relays the signature to a running `autopen serve` (the `remoteKey` bundles the
  socket path + file-reference handle). The signing certificate (`cert`, whose
  key MUST match the token key) supplies the shim's objects.

  Requires the autopen socket to be present in the build sandbox — the builder
  must set `nix.settings.extra-sandbox-paths` for the socket directory and
  advertise the `autopen` system-feature (see the ops wiring, Phase 2).

  # Inputs

  `apk` : the APK to re-sign.
  `cert` : the signer's X.509 certificate (PEM or DER); matches the token key.
  `remoteKey` : an autopen `Remote` signing key file.
  `keyAlias` (optional) : the token key/cert label (default `key`).
  `minSdkVersion` (optional) : apksigner `--min-sdk-version` (default 24, for v2/v3).
  `name` (optional) : output APK name.
  `requiredSystemFeatures` (optional) : defaults to `[ "autopen" ]`.
  `meta` (optional) : derivation metadata.

  # Type

  ```
  signApk :: { apk, cert, remoteKey, keyAlias?, minSdkVersion?, name?,
               requiredSystemFeatures?, meta? } -> Derivation
  ```
*/
{
  apk,
  cert,
  remoteKey,
  keyAlias ? "key",
  minSdkVersion ? 24,
  name ? "signed.apk",
  requiredSystemFeatures ? [ "autopen" ],
  meta ? { },
}:
hideDerivation (
  runCommand name
    {
      inherit requiredSystemFeatures meta;
      # A signed APK has no store references; keep build-time secrets
      # (cert/remoteKey/JDK) out of the output closure.
      allowedRequisites = [ ];
      strictDeps = true;
      __structuredAttrs = true;
      passthru = { inherit cert; };
      env = {
        AUTOPEN_CERT = cert;
        AUTOPEN_REMOTE_KEY = remoteKey;
        AUTOPEN_LABEL = keyAlias;
        JAVA_HOME = jdk;
      };
    }
    ''
      # Register SunPKCS11 by name (--ks-provider-class fails on modern JDKs).
      cfg="$PWD/sunpkcs11.cfg"
      printf 'name = autopen\nlibrary = %s\nslotListIndex = 0\n' ${lib.escapeShellArg shim} > "$cfg"
      printf 'security.provider.12=SunPKCS11 %s\n' "$cfg" > "$PWD/java.security"
      export _JAVA_OPTIONS="-Djava.security.properties=$PWD/java.security"

      ${inner} sign --ks NONE --ks-type PKCS11 \
        --ks-provider-name SunPKCS11-autopen \
        --ks-key-alias "$AUTOPEN_LABEL" --ks-pass pass:autopen \
        --min-sdk-version ${toString minSdkVersion} \
        --out "$out" ${apk}

      # Fail closed: the re-signed APK must verify (v2/v3) before we emit it.
      ${inner} verify --min-sdk-version ${toString minSdkVersion} "$out"
    ''
)
