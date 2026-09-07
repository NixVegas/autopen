<!--
SPDX-FileCopyrightText: 2026 Emily <hello@emily.moe>

SPDX-License-Identifier: BlueOak-1.0.0
-->

# autopen

A cryptographic signing service with an object‐capability interface.

This is currently a basic prototype supporting software keys and signing over
Unix sockets, modelling durable references to signing capabilities using the
identities of accessible files; it is not yet ready for production and you
shouldn’t use it for anything.

Forthcoming are support for signing over the network, better signature
algorithms, hardware‐backed keys, and transparency logs.

There is a
[detailed explanation of the design from a Nix perspective](docs/nix-perspective.md),
covering its suitability for integrating signing into Nix builds while
maintaining essential reproducibility properties.

## Building

Building autopen requires Rust 1.95 or later, and the
[Cap’n Proto](https://capnproto.org/) `capnp(1)` tool. This repository includes
a Nix flake with an `autopen` package.

## Usage

You can create a software signing key, obtain its corresponding verification
key, sign a message, and then verify it:

```console
$ autopen signing-key software rsa3072-pkcs1-sha256 generate \
    --output test-signing-key
$ autopen signing-key get-verification-key \
    --signing-key test-signing-key \
    --output test-verification-key
$ printf 'squeamish ossifrage\n' > test-message
$ autopen sign \
    --signing-key test-signing-key \
    --output test-signature \
    test-message
$ autopen verify \
    --verification-key test-verification-key \
    --signature test-signature \
    test-message
```

You can also provide access to signing keys over a Unix socket without exposing
the key material to clients:

```console
$ mkdir test-key-reference
$ autopen signing-key remote create \
    --socket-path test-socket \
    --file-ref-path test-key-reference \
    --verification-key test-verification-key \
    --output test-remote-key
$ autopen serve \
    --socket-path test-socket \
    --signing-key-ref test-key-reference test-signing-key
```

Then, in another shell:

```console
$ printf 'hapax legomenon\n' > test-message-2
$ autopen sign \
    --signing-key test-remote-key \
    --output test-signature-2 \
    test-message-2
$ autopen verify \
    --verification-key test-verification-key \
    --signature test-signature-2 \
    test-message-2
```

To use the key, clients must be able to connect to the socket path encoded in
the remote key, and open the file reference path to pass as a file description
over that socket.

See `autopen --help` for more detail, including utility commands to produce
self‐signed X.509 code signing certificates.

### Hardware (PKCS#11) keys

`autopen serve` can back a remote key with a private key held in a PKCS#11 token
(a hardware security module such as a YubiHSM, or a software token such as
[kryoptic](https://github.com/latchset/kryoptic) for testing) instead of a
software key file. The token key never leaves the device, and — crucially — the
PKCS#11 module path and PIN never enter the persisted remote key or the wire
protocol: clients still hold only a plain `Remote` key, so hardware‐ness is
entirely a `serve`‐side concern.

The token key is selected with a single
[RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) `pkcs11:` URI carrying the
module path, a token selector, the object, and a PIN source:

```text
pkcs11:token=YubiHSM;id=%01;type=private;module-path=/path/to/module.so;pin-source=file:/run/keys/hsm.pin
```

`pin-value` is rejected (a secret must never be embedded in a URI) and
`pin-source` is restricted to the `file:` scheme; only a *path* appears in the
URI, so the URI itself is not secret, while the referenced file must stay
owner‐only (`0600`). Only RSA‐3072 PKCS#1 v1.5 SHA‐256 keys are supported, and
the token performs the hashing (mechanism `CKM_SHA256_RSA_PKCS`) — autopen does
no software hashing or DigestInfo assembly.

Export the token's verification key, then serve a remote key backed by it:

```console
$ autopen signing-key hardware get-verification-key \
    --pkcs11-uri "$uri" \
    --output test-verification-key
$ mkdir test-key-reference
$ autopen signing-key remote create \
    --socket-path test-socket \
    --file-ref-path test-key-reference \
    --verification-key test-verification-key \
    --output test-remote-key
$ autopen serve \
    --socket-path test-socket \
    --hardware-key "$uri" test-key-reference
```

`--hardware-key` is repeatable and may be mixed with `--signing-key-ref`, so a
single daemon can serve several hardware and software keys side by side, each
bound to its own file reference (and, for hardware keys, its own URI and PIN
source). Clients then sign against `test-remote-key` exactly as in the software
remote‐key example above.

#### PKCS#11 client shim

The workspace also builds `libautopen_pkcs11.so`, a minimal sign‐only PKCS#11
*provider* that lets an unmodified PKCS#11 consumer (for example `apksigner` via
Java's SunPKCS11) sign through an autopen remote key. The shim links no token
library and holds no key material; its `C_Sign*` entry points relay the message
to `autopen serve` over the capability socket. It presents proxy private‐key,
public‐key, and certificate objects derived from the signer's X.509 certificate,
and is configured entirely through the environment:

| Variable | Required | Meaning |
| --- | --- | --- |
| `AUTOPEN_REMOTE_KEY` | yes | path to the `Remote` key the shim signs with |
| `AUTOPEN_CERT` | yes | the signer's X.509 certificate (PEM or DER); supplies the proxy objects and must match the token key |
| `AUTOPEN_LABEL` | no | the `CKA_LABEL` advertised for the proxy key/cert (the consumer's key alias) |
| `AUTOPEN_ID` | no | the `CKA_ID` advertised for the proxy objects |

To drive it from a modern JDK, register the provider by name (the JDK‐8
`SunPKCS11(String)` constructor used by `--ks-provider-class` was removed):

```console
$ cat > sunpkcs11.cfg <<EOF
name = autopen
library = /path/to/libautopen_pkcs11.so
slotListIndex = 0
EOF
$ printf 'security.provider.12=SunPKCS11 %s\n' "$PWD/sunpkcs11.cfg" > java.security
$ export _JAVA_OPTIONS="-Djava.security.properties=$PWD/java.security"
$ apksigner sign --ks NONE --ks-type PKCS11 \
    --ks-provider-name SunPKCS11-autopen \
    --ks-key-alias "$AUTOPEN_LABEL" --ks-pass pass:autopen \
    --min-sdk-version 24 --out signed.apk app.apk
```

SunPKCS11 requires a full JDK (the `jdk.crypto.cryptoki` module); `apksigner`'s
bundled minimal JRE does not include it. The `autopen.lib.signApk` Nix helper
(see below) encodes this whole recipe.

### Nix library

There is a Nix library for integrating autopen signing, accessible as
`autopen.lib` and implemented in `nix/lib.nix`.

There is currently no documentation, but the following tests may be helpful for
understanding the API:

* `autopen.mkTest` (`nix/autopen/tests/default.nix`) takes a caller‐specified
  signing key and produces an X.509 code signing certificate for it. On Linux,
  the certificate is then used to sign the fwupd UEFI executable from Nixpkgs.
* `autopen.tests.softwareKey` instantiates `autopen.test` with a test software
  key.
* `autopen.remoteKeyTest` (`nix/autopen/tests/remote.nix`) contains
  `autopen.remoteKeyTest.server`, which starts a signing server on
  `/tmp/autopen/socket` when run, and `autopen.remoteKeyTest.test`, which
  instantiates `autopen.test` with the corresponding remote signing key. After
  starting the server, you can then build the test with
  `--extra-sandbox-paths /tmp/autopen`.
* `autopen.tests.nixos` (`nix/autopen/tests/nixos.nix`) is an end‐to‐end NixOS
  VM test that runs autopen as a sandboxed systemd service and automates the
  remote test build.
* `autopen.lib.signApk` (`nix/autopen/lib/sign-apk.nix`) re‐signs an APK with a
  hardware‐backed remote key, driving `apksigner` through the PKCS#11 shim. It
  requires the autopen socket in the build sandbox (via
  `nix.settings.extra-sandbox-paths`) and the `autopen` system feature.

The `nix/autopen/tests` directory also contains two runnable shell reproducers,
`hardware-e2e.sh` (a kryoptic token → `serve` → `sign` round trip) and
`apk-e2e.sh` (the full `apksigner` → shim → `serve` → token slice), which are
the end‐to‐end proofs for the hardware backend and the PKCS#11 shim.

## Funding

This project is funded through
[NGI Fediversity Fund](https://nlnet.nl/fediversity/), a fund established by
[NLnet](https://nlnet.nl/) with financial support from the European Commission’s
[Next Generation Internet](https://ngi.eu/) programme. Learn more at the
[NLnet project page](https://nlnet.nl/project/NixOS-verifiedboot/).

## Licence

autopen is available under the
[Blue Oak Model License 1.0.0](LICENSES/BlueOak-1.0.0.txt). The repository is
compliant with the [REUSE](https://reuse.software/) specification.
