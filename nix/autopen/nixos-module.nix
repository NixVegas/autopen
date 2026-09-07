# SPDX-FileCopyrightText: 2026 Emily <hello@emily.moe>
#
# SPDX-License-Identifier: BlueOak-1.0.0

# A NixOS module for the autopen signing daemon (`autopen serve`).
#
# Exposes signing keys over a capability Unix socket without the key material
# reaching clients. Keys may be software keys (loaded via a systemd credential)
# or hardware keys held in a PKCS#11 token (a TPM, a YubiHSM, or a software
# token like kryoptic). Sandboxed nix builds can sign through the socket when
# `exposeToSandbox` is set.
#
# The socket is systemd-activated: systemd binds it (with the configured group
# and mode) and passes the fd to `autopen serve`, so the daemon needs no
# socket-creation privilege of its own.
#
# ## File references (the object capability)
#
# Every key is bound to a *file reference*: a path the server opens at startup
# and whose `(st_dev, st_ino)` identity it records. A client may only name the
# key by opening the *same file* and passing it over the socket — so read access
# to the ref file IS the capability to request signatures with that key.
#
# For sandboxed nix builds, the ref must therefore be a **store path** (visible
# in every sandbox, stable identity, world-readable). Produce it with
# `autopen.lib.signingKey.remote` and give the SAME `fileRefPath` to this module
# (server) and to the build that signs (client). Do not invent an out-of-store
# path here: a `/var/lib/...` file is not in the build sandbox and cannot be
# opened by the signing derivation.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    escapeShellArg
    mapAttrsToList
    mkEnableOption
    mkIf
    mkOption
    mkPackageOption
    optional
    types
    ;

  cfg = config.services.autopen;

  fileRefOption = mkOption {
    type = types.path;
    example = lib.literalExpression "autopenLib.signingKey.remote { inherit name verificationKey; }.fileRefPath";
    description = ''
      The object-capability file reference the key is bound to: a **store path**
      (an empty directory) produced by `autopen.lib.signingKey.remote`. The same
      path must appear in the signing build's closure — that store-path
      membership is what authorizes the build to use this key.
    '';
  };

  hardwareKeyType = types.submodule {
    options = {
      uri = mkOption {
        type = types.str;
        example = "pkcs11:token=key;id=%01;type=private;module-path=/…/libtpm2_pkcs11.so;pin-source=file:/etc/…/user.pin";
        description = ''
          The RFC 7512 `pkcs11:` URI selecting the token key: it must carry
          `module-path`, a token/object selector, and `pin-source=file:<path>`
          for login. The referenced pin file must be owner-only (`0600`).
        '';
      };
      fileRef = fileRefOption;
    };
  };

  softwareKeyType = types.submodule {
    options = {
      keyFile = mkOption {
        type = types.path;
        description = "Path to the persisted software signing key (loaded as a systemd credential; never world-readable).";
      };
      fileRef = fileRefOption;
    };
  };

  # `autopen serve …` via a wrapper script so PKCS#11 URIs (which contain `%`
  # and `;`) are shell-quoted, not mangled by systemd's specifier/argument
  # parsing. No `--socket-path`: the listener comes from socket activation.
  #
  # Each `\`-continued arg is prefixed (not joined) so an empty key set can't
  # leave a dangling trailing backslash.
  keyArgs =
    (mapAttrsToList (
      name: key: ''--signing-key-ref ${escapeShellArg (toString key.fileRef)} "$CREDENTIALS_DIRECTORY/${name}"''
    ) cfg.softwareKeys)
    ++ (mapAttrsToList (
      _name: key: "--hardware-key ${escapeShellArg key.uri} ${escapeShellArg (toString key.fileRef)}"
    ) cfg.hardwareKeys);

  serveScript = pkgs.writeShellScript "autopen-serve" ''
    exec ${lib.getExe cfg.package} serve \
      --log ${escapeShellArg cfg.logLevel}${lib.concatMapStrings (arg: " \\\n      " + arg) keyArgs}
  '';
in
{
  options.services.autopen = {
    enable = mkEnableOption "the autopen signing daemon";

    package = mkPackageOption pkgs "autopen" { };

    logLevel = mkOption {
      type = types.str;
      default = "info";
      description = "The `--log` level passed to `autopen serve`.";
    };

    socketPath = mkOption {
      type = types.nullOr types.str;
      default = "/run/autopen/socket";
      description = ''
        Path the capability socket is systemd-activated on. When null, no socket
        unit is defined — bring your own `systemd.sockets.autopen` (the daemon
        always takes its listener from socket activation).
      '';
    };

    socketGroup = mkOption {
      type = types.str;
      default = "nixbld";
      description = "The group that owns the socket (and so may connect to sign). Defaults to the nix build group.";
    };

    socketMode = mkOption {
      type = types.str;
      default = "0660";
      description = "The mode of the capability socket.";
    };

    supplementaryGroups = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "tpm2-pkcs11" ];
      description = ''
        Extra supplementary groups for the daemon, e.g. a group guarding the
        PKCS#11 token store. `tss` is added automatically when `tpm` is set.
      '';
    };

    hardwareKeys = mkOption {
      type = types.attrsOf hardwareKeyType;
      default = { };
      description = "PKCS#11 token-backed signing keys, by name.";
    };

    softwareKeys = mkOption {
      type = types.attrsOf softwareKeyType;
      default = { };
      description = "Software signing keys, by name.";
    };

    tpm = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Relax the service hardening enough to reach a TPM: adds the `tss` group
        and `/dev/tpmrm0`, and permits the `AF_UNIX` socket used to talk to
        tpm2-abrmd over the D-Bus system bus.
      '';
    };

    exposeToSandbox = mkOption {
      type = types.bool;
      default = true;
      description = "Add the socket's directory to `nix.settings.extra-sandbox-paths` so sandboxed builds can reach it.";
    };

    extraServiceConfig = mkOption {
      type = types.attrs;
      default = { };
      description = "Extra `serviceConfig` merged into the systemd service (e.g. to tighten or loosen hardening).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.hardwareKeys != { } || cfg.softwareKeys != { };
        message = "services.autopen: define at least one of hardwareKeys or softwareKeys.";
      }
    ];

    # systemd binds the socket in the sign-capable group and passes the fd to the
    # (socket-activated) service. Binding it also creates the parent directory.
    systemd.sockets.autopen = mkIf (cfg.socketPath != null) {
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = cfg.socketPath;
        SocketGroup = cfg.socketGroup;
        SocketMode = cfg.socketMode;
      };
    };

    systemd.services.autopen = {
      # No wantedBy: started on first connection to autopen.socket.
      serviceConfig = {
        Type = "exec";
        ExecStart = serveScript;

        DynamicUser = true;
        UMask = "0077";

        LoadCredential = mapAttrsToList (name: key: "${name}:${toString key.keyFile}") cfg.softwareKeys;

        SupplementaryGroups = optional cfg.tpm "tss" ++ cfg.supplementaryGroups;
        DeviceAllow = optional cfg.tpm "/dev/tpmrm0 rw";
        PrivateDevices = !cfg.tpm;
        # tpm2-abrmd (D-Bus system bus) + the client pidfd/cgroup live behind
        # AF_UNIX; with no TPM the daemon needs no address families at all
        # (the listening socket fd is handed in by systemd).
        RestrictAddressFamilies = if cfg.tpm then [ "AF_UNIX" ] else "none";
        PrivateNetwork = true;

        CapabilityBoundingSet = [ "" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        # NOTE: do NOT set ProtectProc = "invisible". Peer attestation reads the
        # connecting client's /proc/<pid>/cgroup, and the client (a nix builder)
        # runs as a different uid than this DynamicUser daemon — hidepid=invisible
        # would hide it and every signature would fail with "Failed to attest
        # peer". ProcSubset=pid is fine: it only hides non-process /proc files.
        ProcSubset = "pid";
        # Likewise keep /sys/fs/cgroup readable for attestation (not strict).
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        IPAddressDeny = "any";
      }
      // cfg.extraServiceConfig;
    };

    nix.settings.extra-sandbox-paths = mkIf (cfg.exposeToSandbox && cfg.socketPath != null) [
      (builtins.dirOf cfg.socketPath)
    ];
  };
}
