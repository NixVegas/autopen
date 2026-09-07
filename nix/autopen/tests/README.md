<!--
SPDX-FileCopyrightText: 2026 Morgan Jones

SPDX-License-Identifier: BlueOak-1.0.0
-->

# Hardware-signing test notes (`treewide/hardware-signing`)

Substrate for the PKCS#11 hardware backend + client shim. In CI/dev we use
**kryoptic** (a software PKCS#11 token) as a stand-in for the YubiHSM; the
backend and shim are PKCS#11-agnostic, so kryoptic↔YubiHSM is a config-only
swap.

The devshell (`nix develop`) provides `kryoptic` (`libkryoptic_pkcs11.so`),
`opensc` (`pkcs11-tool`), and `openssl`.

## Dependency decisions (Task 0)

- **`cryptoki` v0.12** is the PKCS#11 *consumer* binding used by the hardware
  backend. It is added in Task 1 (when first used), not Task 0, because
  `unused-crate-dependencies` is active and would warn on an unused dep.
- **`pkcs11-uri` is rejected.** v0.1.3 pulls in the unmaintained legacy `pkcs11`
  crate (`libloading 0.5.2`, `num-bigint 0.2`, `cc`, winapi) — a second PKCS#11
  binding and a likely `cargo audit`/`deny` hit. RFC 7512 is trivial, so we
  hand-parse the `pkcs11:` URI in `src/signing_key/hardware/uri.rs`.

## Initialise a kryoptic token with an RSA-3072 key (verified working)

```bash
export KRYOPTIC_CONF="$PWD/token.conf"
cat > "$KRYOPTIC_CONF" <<EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "$PWD/token.sql"
EOF
mod=$(nix build --no-link --print-out-paths nixpkgs#kryoptic)/lib/libkryoptic_pkcs11.so

pkcs11-tool --module "$mod" --init-token --label test --so-pin 0000
pkcs11-tool --module "$mod" --init-pin --so-pin 0000 --login --pin 1234
pkcs11-tool --module "$mod" --login --pin 1234 \
  --keypairgen --key-type rsa:3072 --id 01 --label test
pkcs11-tool --module "$mod" --login --pin 1234 --list-objects
```

The private key lists as `id 01`, `Usage: sign`, and kryoptic reports its URI
as:

```text
pkcs11:model=v1;manufacturer=Kryoptic%20Project;serial=…;token=test;id=%01;object=test;type=private
```

For autopen we build the URI ourselves, adding `module-path=$mod` and
`pin-source=file:<pin file>` (the two attrs nixpkcs also emits), e.g.:

```text
pkcs11:token=test;id=%01;type=private;module-path=<so>;pin-source=file:<pin>
```
