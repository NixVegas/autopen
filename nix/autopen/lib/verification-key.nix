{
  lib,
  runCommand,
  openssl,
  capnproto,
}:

let
  schema = ../../../schema/autopen.capnp;
in

/**
  Build an autopen verification key from existing public-key material.

  autopen's on-disk verification key is a binary Cap'n Proto message, not a
  PEM, so a certificate or public key cannot be handed to autopen directly.
  These helpers extract the RSA public key and repackage it into the
  `verificationKey` file autopen expects (`autopen sign`/`verify`,
  `signingKey.remote { verificationKey = …; }`).
*/
{
  /**
    Build an autopen verification key from an X.509 certificate or a bare RSA
    public key.

    Accepts, and auto-detects: an X.509 certificate (PEM or DER), an SPKI
    public key (`-----BEGIN PUBLIC KEY-----`), or a PKCS#1 `RSAPublicKey`
    (`-----BEGIN RSA PUBLIC KEY-----`), in PEM or DER. The RSA modulus size
    selects the algorithm (2048 → `rsa2048-pkcs1-sha256`, 3072 →
    `rsa3072-pkcs1-sha256`).

    # Inputs

    `source`
    : Path to the certificate or public key. May be passed positionally, or as
      the `source` attribute of an attrset alongside `hash`.

    `hash` (optional)
    : The SRI content hash of the emitted verification-key file. When given, the
      builder becomes a fixed-output derivation, so its output is
      content-addressed (a nixpkgs-independent store path) and it exposes
      `passthru.handleSeed` (the same hash in base16). `signingKey.remote` uses
      that seed for its `fileRefPath` with no import-from-derivation. The
      verification-key encoding is deterministic, so the hash is stable per key;
      compute it once (`nix hash file` on the output) and commit it. Omit it to
      keep the legacy input-addressed build (remote then falls back to hashFile,
      an IFD).

    # Type

    ```
    fromCertificate :: (Path | { source :: Path, hash :: String | Null }) -> Derivation
    ```
  */
  fromCertificate =
    arg:
    let
      source = if builtins.isAttrs arg then arg.source else arg;
      hash = if builtins.isAttrs arg then (arg.hash or null) else null;
    in
    runCommand "autopen-verification-key"
      (
        {
          nativeBuildInputs = [
            openssl
            capnproto
          ];
          inherit source;
          passthru = lib.optionalAttrs (hash != null) {
            handleSeed = builtins.convertHash {
              inherit hash;
              toHashFormat = "base16";
              hashAlgo = "sha256";
            };
          };
        }
        // lib.optionalAttrs (hash != null) {
          outputHashMode = "flat";
          outputHashAlgo = "sha256";
          outputHash = hash;
        }
      )
      ''
        set -euo pipefail

        # Extract the SPKI public key from a certificate (PEM or DER); if the
        # input is not a certificate, assume it is already a public key.
        if openssl x509 -in "$source" -pubkey -noout > pub.pem 2>/dev/null \
          || openssl x509 -inform DER -in "$source" -pubkey -noout > pub.pem 2>/dev/null; then
          :
        else
          cp "$source" pub.pem
        fi

        # Normalise to a PKCS#1 RSAPublicKey DER, whatever the input encoding.
        if   openssl rsa -pubin              -in pub.pem              -RSAPublicKey_out -outform DER -out pkcs1.der 2>/dev/null; then :
        elif openssl rsa -pubin -inform DER  -in pub.pem              -RSAPublicKey_out -outform DER -out pkcs1.der 2>/dev/null; then :
        elif openssl rsa -RSAPublicKey_in    -in pub.pem                                -outform DER -out pkcs1.der 2>/dev/null; then :
        elif openssl rsa -RSAPublicKey_in -inform DER -in pub.pem                        -outform DER -out pkcs1.der 2>/dev/null; then :
        else
          echo "autopen verification-key: not an X.509 certificate or RSA public key: $source" >&2
          exit 1
        fi

        # The modulus size selects the algorithm variant.
        modhex=$(openssl rsa -RSAPublicKey_in -inform DER -in pkcs1.der -modulus -noout | sed 's/^Modulus=//')
        case "$(( ''${#modhex} / 2 ))" in
          256) arm=rsa2048Pkcs1Sha256 ;;
          384) arm=rsa3072Pkcs1Sha256 ;;
          *) echo "autopen verification-key: unsupported RSA modulus ($(( ''${#modhex} / 2 )) bytes; expected 256 or 384)" >&2; exit 1 ;;
        esac

        # Wrap the PKCS#1 DER into the autopen verification-key Cap'n Proto file.
        hex=$(od -An -v -tx1 pkcs1.der | tr -d ' \n')
        printf '(verificationKey = (%s = (pkcs1Der = 0x"%s")))' "$arm" "$hex" \
          | capnp encode ${schema} Local.File > "$out"
      '';
}
