{
  lib,
  callPackage,
  stdenv,
  rustPlatform,
  capnproto,
  autopen,
  testers,
  pkgsLinux,
}:

rustPlatform.buildRustPackage {
  pname = "autopen";
  version = "0.2.0";

  src =
    let
      cargoToml = lib.importTOML ../../Cargo.toml;
    in
    lib.fileset.toSource {
      root = ../../.;
      fileset = lib.fileset.unions (map (subPath: ../../. + subPath) cargoToml.package.include);
    };

  cargoLock = {
    lockFile = ../../Cargo.lock;
    outputHashes = {
      "capnp-0.26.2" = "sha256-K7Loo9KhZ0wUY/NMrgu1WkftA4MBF2m43ZzCwVr0YAk=";
    };
  };

  nativeBuildInputs = [
    capnproto
  ];

  useNextest = true;

  # Build the whole workspace so the PKCS#11 shim cdylib (a member nothing else
  # depends on) is compiled, not just the `autopen` binary.
  cargoBuildFlags = [ "--workspace" ];

  cargoTestFlags = [ "--max-fail=all" ];

  strictDeps = true;

  __structuredAttrs = true;

  # The workspace also builds the sign-only PKCS#11 client shim (a cdylib);
  # buildRustPackage installs binaries but not cdylibs, so install it here.
  # Consumers reference it as `${autopen}/lib/libautopen_pkcs11.so`.
  #
  # The cargo-* check derivations (clippy/doc/audit/deny) reuse this package via
  # `overrideAttrs` but skip the cargo install (`dontCargoInstall`) and never
  # build the release cdylib, so only install it in the real build.
  postInstall = ''
    if [ -z "''${dontCargoInstall:-}" ]; then
      mkdir -p "$out/lib"
      cp target/*/release/libautopen_pkcs11.so "$out/lib/"
    fi
  '';

  passthru = {
    lib = callPackage ./lib { };

    mkTest = callPackage ./tests { };

    testSigningKey = autopen.lib.signingKey.import {
      name = "autopen-test-rsa3072-pkcs1-sha256";
      path = ./tests/test-rsa3072-pkcs1-sha256-signing-key.bin;
    };

    remoteKeyTest = callPackage ./tests/remote.nix { };

    tests = {
      softwareKey = autopen.mkTest {
        signingKey = autopen.testSigningKey;
      };

      nixos = testers.runNixOSTest {
        imports = [ ./tests/nixos.nix ];
        _module.args = {
          inherit (pkgsLinux) autopen;
        };
      };
    };
  };

  meta = {
    description = "Cryptographic signing tool with an object‐capability interface";
    homepage = "https://github.com/emilazy/autopen";
    license = lib.licenses.blueOak100;
    sourceProvenance = [ lib.sourceTypes.fromSource ];
    maintainers = [ lib.maintainers.emily ];
    mainProgram = "autopen";
    platforms = lib.platforms.unix;
  };
}
