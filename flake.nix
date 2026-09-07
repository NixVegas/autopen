# SPDX-FileCopyrightText: 2026 Emily <hello@emily.moe>
#
# SPDX-License-Identifier: BlueOak-1.0.0

{
  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rustsec-advisory-db = {
      url = "github:RustSec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      rustsec-advisory-db,
    }:
    let
      inherit (nixpkgs.lib)
        attrValues
        extends
        genAttrs
        makeScope
        ;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      eachSystem = f: genAttrs systems (system: f system nixpkgs.legacyPackages.${system});

      treefmtEval = eachSystem (_system: pkgs: treefmt-nix.lib.evalModule pkgs ./nix/treefmt.nix);

      devChecks = eachSystem (
        system: pkgs:
        {
          reuse = pkgs.runCommand "reuse-check" { nativeBuildInputs = [ pkgs.reuse ]; } ''
            cd ${self}
            reuse lint
            touch $out
          '';

          treefmt = treefmtEval.${system}.config.build.check self;
        }
        // pkgs.callPackages ./nix/cargo-checks.nix {
          inherit (self.packages.${system}) autopen;
          inherit rustsec-advisory-db;
        }
      );
    in
    {
      packages = eachSystem (
        _system: pkgs:
        let
          scope = makeScope pkgs.newScope (
            extends self.overlays.default (_self: {
              pkgsLinux = makeScope pkgs.pkgsLinux.newScope (_self: {
                inherit (self.packages.${pkgs.pkgsLinux.stdenv.hostPlatform.system}) autopen;
              });
            })
          );
        in
        {
          inherit (scope) autopen;
          default = scope.autopen;
        }
      );

      overlays.default = final: _prev: {
        autopen = (final.callPackage ./nix/autopen/package.nix { }).overrideAttrs (
          finalPackage: previousPackage: {
            passthru = (previousPackage.passthru or { }) // {
              # A nixpkcs-style PKCS#11 module descriptor for the client shim, so
              # nixpkcs can mint URIs (module-path=libautopen_pkcs11.so) that route
              # signing through the autopen daemon rather than the token directly.
              # The daemon holds the PIN, so there is no pin-source and login is a
              # no-op; per-key `remoteKey`/`cert` are supplied via mkEnv.
              pkcs11Module = {
                path = "${finalPackage.finalPackage}/lib/libautopen_pkcs11.so";
                openSslOptions = {
                  pkcs11-module-login-behavior = "never";
                };
                mkEnv =
                  {
                    remoteKey,
                    cert,
                    label ? "autopen",
                    id ? null,
                    extraEnv ? { },
                  }:
                  {
                    AUTOPEN_REMOTE_KEY = toString remoteKey;
                    AUTOPEN_CERT = toString cert;
                    AUTOPEN_LABEL = label;
                  }
                  // final.lib.optionalAttrs (id != null) { AUTOPEN_ID = id; }
                  // extraEnv;
              };
            };
          }
        );
      };

      # The `services.autopen` NixOS module. Apply `overlays.default` for the
      # `autopen` package it defaults to.
      nixosModules.default = import ./nix/autopen/nixos-module.nix;
      nixosModules.autopen = self.nixosModules.default;

      checks = eachSystem (
        system: _pkgs:
        {
          inherit (self.packages.${system}) default;
        }
        // self.packages.${system}.default.tests
        // devChecks.${system}
      );

      devShells = eachSystem (
        system: pkgs: {
          default = pkgs.mkShell {
            inputsFrom = attrValues devChecks.${system};

            packages = [
              pkgs.rust-analyzer
              # Hardware-signing (treewide/hardware-signing): a software PKCS#11
              # token for hermetic tests (kryoptic), a CLI to drive it (opensc's
              # pkcs11-tool), and openssl for signature verification.
              pkgs.kryoptic
              pkgs.opensc
              pkgs.openssl
            ]
            ++ attrValues treefmtEval.${system}.config.build.programs;
          };
        }
      );

      formatter = eachSystem (system: _pkgs: treefmtEval.${system}.config.build.wrapper);
    };
}
