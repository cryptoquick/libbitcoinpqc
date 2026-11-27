# Nix loads flake.nix. The body is repro.nix.
# Nix 2.36 requires this file to be a trivial attribute set. A bare import
# is rejected, so the outputs function calls repro.nix.
{
  description = "Reproduce the SLH-DSA rejection of origin/main at 053e954";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/18b9261cb3294b6d2a06d03f96872827b8fe2698";
    systems.url = "github:nix-systems/default";
    # Present so origin/main's nested flake can follow this input.
    flake-parts.url = "github:hercules-ci/flake-parts";

    secp256k1 = {
      url = "git+https://github.com/bitcoin-core/secp256k1?rev=1a53f4961f337b4d166c25fce72ef0dc88806618";
      flake = false;
    };

    libbitcoinpqc-main = {
      url = "github:cryptoquick/libbitcoinpqc/053e954534b13c1dbdc8ef4f9ae4d93bb301bab6";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
      inputs.systems.follows = "systems";
      inputs.secp256k1.follows = "secp256k1";
    };

    # Parent tree, not a flake. flake = false prevents a cycle.
    libbitcoinpqc-src = {
      url = "path:..";
      flake = false;
    };
  };

  outputs = inputs: import ./repro.nix inputs;
}
