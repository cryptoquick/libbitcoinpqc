# This flake reproduces the SLH-DSA failure of origin/main at
# 053e954534b13c1dbdc8ef4f9ae4d93bb301bab6, the parent of 07b227d.
# That commit signs and verifies the raw message. message_to_indices uses
# the SPHINCS+ 3.1 order: (offset & 0x7) placed with << j.
# This tree prefixes the message with 0x00 || 0x00 and uses the FIPS 205
# FORS bit order. This tree uses pure mode with an empty context. Pre-hash
# and a caller context are not offered.
# The driver is tests/slh_dsa_sha2_openssl.c from this tree. The library
# under test is main's installed package. The driver calls
# bitcoin_pqc_verify only.
# got -3 is BITCOIN_PQC_ERROR_BAD_SIGNATURE. expected 0 is BITCOIN_PQC_OK.
# The two lines for the valid signatures are the proof. A non-zero exit
# alone is not the proof.
# slh_dsa_derandomize hashes the raw message. That domain byte is not the
# FIPS prefix. OpenSSL hedged signatures are not required to byte-match.
# The longer write-up is SECURITY.md at the repository root.
inputs @ {
  nixpkgs,
  libbitcoinpqc-main,
  libbitcoinpqc-src,
  ...
}: let
  lib = nixpkgs.lib;
in {
  checks = lib.genAttrs (import inputs.systems) (system: let
    pkgs = import nixpkgs {inherit system;};
    mainPkg = libbitcoinpqc-main.packages.${system}.libbitcoinpqc;
    # path:.. can see build/ and result. Drop them so this check does not
    # hash the local build tree.
    src = lib.cleanSourceWith {
      src = libbitcoinpqc-src;
      filter = path: type: let
        base = baseNameOf path;
      in
        !(base == "build" && type == "directory")
        && !(base == "result" || lib.hasPrefix "result-" base)
        && lib.cleanSourceFilter path type;
    };
  in {
    slh-dsa-main-rejects-openssl =
      pkgs.runCommand "slh-dsa-main-rejects-openssl" {
        nativeBuildInputs = [pkgs.stdenv.cc];
      } ''
        set -euo pipefail
        $CC -std=c99 -O2 -o slh_dsa_sha2_openssl \
          ${src}/tests/slh_dsa_sha2_openssl.c \
          -I${mainPkg}/include \
          -I${src}/tests \
          ${mainPkg}/lib/libbitcoinpqc.a \
          ${mainPkg}/lib/libsecp256k1.a \
          -lpthread -lm
        set +e
        ./slh_dsa_sha2_openssl > driver.txt
        status=$?
        set -e
        cat driver.txt
        if [ "$status" -eq 0 ]; then
          echo "driver exited 0" >&2
          exit 1
        fi
        grep -F -q "baseline valid signature: got -3 expected 0" driver.txt
        grep -F -q "valid signature over empty message: got -3 expected 0" driver.txt
        grep -F -q "bit flip in the signature: got -3 expected -3" driver.txt
        grep -F -q "signature one byte short: got -3 expected -3" driver.txt
        grep -F -q "signature one byte long: got -3 expected -3" driver.txt
        if grep -F -q "baseline valid signature: got 0 expected 0" driver.txt; then
          echo "baseline signature was accepted" >&2
          exit 1
        fi
        mkdir -p "$out"
        cp driver.txt "$out/driver.txt"
      '';
  });
}
