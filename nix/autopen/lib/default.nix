{ callPackage }:

{
  internal = callPackage ./internal.nix { };
  signingKey = callPackage ./signing-key.nix { };
  sign = callPackage ./sign.nix { };
  signApk = callPackage ./sign-apk.nix { };
  verificationKey = callPackage ./verification-key.nix { };
  x509 = callPackage ./x509.nix { };
  authenticode = callPackage ./authenticode.nix { };
}
