{
  description = "libbitcoinpqc — post-quantum signature primitives for Bitcoin";

  inputs = {
    # Pin nixpkgs by rev for reproducible evaluation (bump intentionally).
    nixpkgs.url = "github:NixOS/nixpkgs/18b9261cb3294b6d2a06d03f96872827b8fe2698";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";

    # Pin matches CMakeLists.txt FetchContent GIT_TAG (v0.7.1).
    # Peeled commit for annotated tag v0.7.1; offline via FETCHCONTENT_SOURCE_DIR.
    secp256k1 = {
      url = "git+https://github.com/bitcoin-core/secp256k1?rev=1a53f4961f337b4d166c25fce72ef0dc88806618";
      flake = false;
    };
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    systems,
    secp256k1,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = import systems;

      perSystem = {
        pkgs,
        system,
        ...
      }: let
        inherit (pkgs) lib;

        src = lib.cleanSourceWith {
          src = ./.;
          filter = path: type: let
            base = baseNameOf path;
          in
            # Local build dirs / nix result links
            !(base == "build" && type == "directory")
            && !(base == "result" || lib.hasPrefix "result-" base)
            && lib.cleanSourceFilter path type;
        };

        libbitcoinpqc = pkgs.stdenv.mkDerivation {
          pname = "libbitcoinpqc";
          version = "0.1.0";
          inherit src;

          nativeBuildInputs = with pkgs; [
            cmake
            ninja
            pkg-config
          ];

          # Network-free FetchContent: use the flake-pinned secp256k1 tree.
          cmakeFlags = [
            "-GNinja"
            "-DCMAKE_BUILD_TYPE=Release"
            "-DBUILD_EXAMPLES=ON"
            "-DBUILD_TESTS=ON"
            "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
            "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1}"
          ];

          doCheck = true;
          checkPhase = ''
            runHook preCheck
            ctest --output-on-failure -V
            runHook postCheck
          '';

          postInstall = ''
            mkdir -p $out/share/doc/libbitcoinpqc
            cp ${src}/README.md $out/share/doc/libbitcoinpqc/
            cp ${src}/LICENSE $out/share/doc/libbitcoinpqc/ 2>/dev/null || true
          '';

          meta = with lib; {
            description = "C library for post-quantum signature algorithms (ML-DSA-44, SLH-DSA-SHA2-128s) and BIP 340 Schnorr";
            homepage = "https://github.com/cryptoquick/libbitcoinpqc";
            license = licenses.mit;
            platforms = platforms.unix;
          };
        };

        # alejandra --check on Nix sources.
        fmt-check =
          pkgs.runCommand "libbitcoinpqc-fmt" {
            nativeBuildInputs = [pkgs.alejandra];
          } ''
            set -euo pipefail
            alejandra --check ${src}/flake.nix
            mkdir -p $out
            echo ok > $out/result
          '';

        # Reject deprecated BIP 360 / soft naming in project-owned sources.
        naming-check =
          pkgs.runCommand "libbitcoinpqc-naming" {
            nativeBuildInputs = [pkgs.ripgrep];
            inherit src;
          } ''
            set -euo pipefail
            cd "$src"
            # Project content only (not gate scripts, which list these as denylist patterns).
            if rg -n \
              --glob '*.md' --glob '*.h' --glob '*.c' \
              --glob '*.yml' --glob '*.yaml' --glob 'CMakeLists.txt' \
              --glob 'build.sh' --glob 'Makefile' \
              --glob '!dilithium/**' --glob '!sphincsplus/**' \
              -e 'QuBit' \
              -e 'P2QRH' -e 'p2qrh' \
              -e 'P2TSH' -e 'p2tsh' \
              -e 'BIP-360' \
              -e 'cryptoquick/bips' \
              .; then
              echo "libbitcoinpqc: forbidden legacy naming found (see matches above)" >&2
              exit 1
            fi
            mkdir -p $out
            echo ok > $out/result
          '';

        # Link a tiny program against the installed static library + headers.
        install-smoke =
          pkgs.runCommand "libbitcoinpqc-install-smoke" {
            nativeBuildInputs = [pkgs.stdenv.cc pkgs.binutils];
          } ''
            set -euo pipefail
            cat > smoke.c <<'EOF'
            #include <libbitcoinpqc/bitcoinpqc.h>
            #include <stdio.h>
            int main(void) {
              if (bitcoin_pqc_public_key_size(BITCOIN_PQC_SECP256K1_SCHNORR) != 32)
                return 1;
              if (bitcoin_pqc_public_key_size(BITCOIN_PQC_ML_DSA_44) != 1312)
                return 2;
              if (bitcoin_pqc_signature_size(BITCOIN_PQC_SLH_DSA_SHA2_128S) != 7856)
                return 3;
              if (bitcoin_pqc_secret_key_size(BITCOIN_PQC_SLH_DSA_SHA2_128S) != 64)
                return 4;
              puts("install-smoke ok");
              return 0;
            }
            EOF
            $CC -std=c99 -O2 -o smoke smoke.c \
              -I${libbitcoinpqc}/include \
              ${libbitcoinpqc}/lib/libbitcoinpqc.a \
              ${libbitcoinpqc}/lib/libsecp256k1.a \
              -lpthread -lm
            ./smoke
            # Public API symbols in the static archive.
            # Dump nm to a file first: `nm | grep -q` under `pipefail` can exit 141
            # (SIGPIPE) when grep closes the pipe early — intermittent locally, fails on CI.
            nm ${libbitcoinpqc}/lib/libbitcoinpqc.a > symbols.txt
            grep -E '[[:space:]]bitcoin_pqc_keygen$' symbols.txt
            grep -E '[[:space:]]bitcoin_pqc_sign$' symbols.txt
            grep -E '[[:space:]]bitcoin_pqc_verify$' symbols.txt
            test -f ${libbitcoinpqc}/include/libbitcoinpqc/bitcoinpqc.h
            test -f ${libbitcoinpqc}/include/libbitcoinpqc/ml_dsa.h
            test -f ${libbitcoinpqc}/include/libbitcoinpqc/slh_dsa.h
            test -f ${libbitcoinpqc}/lib/libbitcoinpqc.so
            mkdir -p $out
            echo ok > $out/result
          '';

        # secp256k1 pin in flake input matches CMakeLists GIT_TAG comment/tag.
        pin-sync-check =
          pkgs.runCommand "libbitcoinpqc-pin-sync" {
            nativeBuildInputs = [pkgs.ripgrep pkgs.gnugrep];
            inherit src;
          } ''
            set -euo pipefail
            # CMake must pin v0.7.1 (or whatever flake documents).
            rg -q 'GIT_TAG[[:space:]]+v0\.7\.1' "$src/CMakeLists.txt"
            rg -q 'v0\.7\.1' "$src/flake.nix"
            rg -q '1a53f4961f337b4d166c25fce72ef0dc88806618' "$src/flake.nix"
            mkdir -p $out
            echo ok > $out/result
          '';
      in {
        packages = {
          default = libbitcoinpqc;
          libbitcoinpqc = libbitcoinpqc;
        };

        # Everything `nix flake check` / `just test` should exercise.
        checks = {
          libbitcoinpqc = libbitcoinpqc; # build + ctest
          fmt = fmt-check;
          naming = naming-check;
          install-smoke = install-smoke;
          pin-sync = pin-sync-check;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [libbitcoinpqc];

          packages = with pkgs; [
            cmake
            ninja
            pkg-config
            clang-tools # clangd / clang-tidy / clang-format
            gdb
            lldb
            valgrind
            ccache
            just
            alejandra
            ripgrep
          ];

          shellHook = ''
            echo "libbitcoinpqc dev shell (hermetic)"
            echo "  cmake $(cmake --version | head -1)"
            echo "  just  $(just --version 2>/dev/null || true)"
            echo ""
            echo "Gate:   just test"
            echo "Build:  just build | just cmake-build"
            echo "Shell:  just shell"
          '';
        };

        formatter = pkgs.alejandra;
      };
    };
}
