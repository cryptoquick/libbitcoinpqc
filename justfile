# libbitcoinpqc development tasks.
# Run `just` to list recipes.
#
# `just test` is the full verification gate (what CI runs): every flake check
# (ctest, fmt, naming, install-smoke, pin-sync), install layout, worktree
# naming scrub, and the host CMake dual-path build+test+smoke.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Quieter evaluation when the git tree is dirty (uncommitted edits).
nix := "nix --option warn-dirty false"

default:
    @just --list

# ── Full gate ────────────────────────────────────────────────────────────────

# Everything we run in CI and before merge.
test: hermetic worktree-naming cmake-test
    @echo ""
    @echo "=== all checks and tests passed ==="

# Aliases.
check: test
ci: test

# Hermetic suite: all flake checks + install layout under ./result.
hermetic:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== nix flake check (ctest, fmt, naming, install-smoke, pin-sync) ==="
    {{nix}} flake check -L
    echo "=== nix build (install layout → ./result) ==="
    {{nix}} build .#libbitcoinpqc -L
    echo "=== install layout ==="
    test -f result/lib/libbitcoinpqc.a
    test -f result/lib/libbitcoinpqc.so
    test -f result/lib/libsecp256k1.a
    test -f result/include/libbitcoinpqc/bitcoinpqc.h
    test -f result/include/libbitcoinpqc/ml_dsa.h
    test -f result/include/libbitcoinpqc/slh_dsa.h
    ls -la result/lib result/include/libbitcoinpqc

# Worktree-wide naming scrub (broader than the cleaned flake src filter).
worktree-naming:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== worktree naming scrub ==="
    # Content files only (not justfile/flake.nix denylist pattern lines).
    run_rg() {
      rg -n \
        --glob '*.md' --glob '*.h' --glob '*.c' \
        --glob '*.yml' --glob '*.yaml' --glob 'CMakeLists.txt' \
        --glob 'build.sh' --glob 'Makefile' \
        --glob '!dilithium/**' --glob '!sphincsplus/**' \
        --glob '!build/**' --glob '!result/**' --glob '!result-*/**' \
        -e 'QuBit' \
        -e 'P2QRH' -e 'p2qrh' \
        -e 'P2TSH' -e 'p2tsh' \
        -e 'BIP-360' \
        -e 'cryptoquick/bips' \
        .
    }
    if command -v rg >/dev/null 2>&1; then
      if run_rg; then
        echo "forbidden legacy naming found" >&2
        exit 1
      fi
      echo "naming scrub clean"
    else
      # Fall back to flake check's naming (already run under hermetic).
      echo "rg not on PATH; flake checks.naming already covered hermetic path"
    fi

# ── Nix ──────────────────────────────────────────────────────────────────────

# Enter the flake dev shell (cmake, ninja, just, clangd, …).
shell:
    {{nix}} develop

# Build static + shared libs → ./result (not a substitute for `just test`).
build:
    {{nix}} build .#libbitcoinpqc -L

# Format Nix files with the flake formatter (alejandra).
fmt:
    {{nix}} fmt

# Check Nix formatting without writing (also part of flake check).
fmt-check:
    {{nix}} develop --command alejandra --check flake.nix

# Show flake inputs / description.
meta:
    {{nix}} flake metadata

# Update flake.lock (all inputs). Review the diff before committing.
update:
    {{nix}} flake update

# Update only the secp256k1 input (keep CMakeLists GIT_TAG in sync).
update-secp:
    {{nix}} flake update secp256k1

# ── Local CMake (host or nix develop; FetchContent may use network) ──────────

# Run a command with cmake on PATH (host, else nix develop).
[private]
_with-cmake +args:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v cmake >/dev/null 2>&1; then
      exec {{args}}
    fi
    if command -v nix >/dev/null 2>&1; then
      echo "(cmake not on PATH; using nix develop)"
      exec {{nix}} develop --command {{args}}
    fi
    echo "cmake not found and nix not available" >&2
    exit 1

# Configure + build into ./build (examples + tests on).
cmake-build:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== CMake configure + build ==="
    # Fresh tree avoids stale FetchContent caches after secp pin bumps.
    rm -rf build
    run_build() {
      if command -v ninja >/dev/null 2>&1; then
        cmake -S . -B build -GNinja \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_EXAMPLES=ON \
          -DBUILD_TESTS=ON
      else
        cmake -S . -B build \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_EXAMPLES=ON \
          -DBUILD_TESTS=ON
      fi
      cmake --build build
    }
    if command -v cmake >/dev/null 2>&1; then
      run_build
    elif command -v nix >/dev/null 2>&1; then
      echo "(cmake not on PATH; using nix develop)"
      {{nix}} develop --command bash -c '
        set -euo pipefail
        if command -v ninja >/dev/null 2>&1; then
          cmake -S . -B build -GNinja \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_EXAMPLES=ON \
            -DBUILD_TESTS=ON
        else
          cmake -S . -B build \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_EXAMPLES=ON \
            -DBUILD_TESTS=ON
        fi
        cmake --build build
      '
    else
      echo "cmake not found and nix not available" >&2
      exit 1
    fi

# ctest + link smoke against the local build tree (dual-path vs Nix sandbox).
cmake-test: cmake-build
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== ctest (build tree) ==="
    run_test() {
      ctest --test-dir build -V --output-on-failure
      echo "=== host install smoke (link against build tree) ==="
      cat > /tmp/libbitcoinpqc-host-smoke.c <<'EOF'
    #include <libbitcoinpqc/bitcoinpqc.h>
    #include <stdio.h>
    int main(void) {
      if (bitcoin_pqc_public_key_size(BITCOIN_PQC_ML_DSA_44) != 1312) return 1;
      if (bitcoin_pqc_signature_size(BITCOIN_PQC_SLH_DSA_SHA2_128S) != 7856) return 2;
      if (bitcoin_pqc_public_key_size(BITCOIN_PQC_SECP256K1_SCHNORR) != 32) return 3;
      puts("host-smoke ok");
      return 0;
    }
    EOF
      cc -std=c99 -O2 -o /tmp/libbitcoinpqc-host-smoke /tmp/libbitcoinpqc-host-smoke.c \
        -Iinclude \
        build/lib/libbitcoinpqc.a \
        build/lib/libsecp256k1.a \
        -lpthread -lm
      /tmp/libbitcoinpqc-host-smoke
    }
    if command -v ctest >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
      run_test
    elif command -v nix >/dev/null 2>&1; then
      echo "(ctest/cc not on PATH; using nix develop)"
      {{nix}} develop --command bash -c '
        set -euo pipefail
        ctest --test-dir build -V --output-on-failure
        cat > /tmp/libbitcoinpqc-host-smoke.c <<'"'"'EOF'"'"'
    #include <libbitcoinpqc/bitcoinpqc.h>
    #include <stdio.h>
    int main(void) {
      if (bitcoin_pqc_public_key_size(BITCOIN_PQC_ML_DSA_44) != 1312) return 1;
      if (bitcoin_pqc_signature_size(BITCOIN_PQC_SLH_DSA_SHA2_128S) != 7856) return 2;
      if (bitcoin_pqc_public_key_size(BITCOIN_PQC_SECP256K1_SCHNORR) != 32) return 3;
      puts("host-smoke ok");
      return 0;
    }
    EOF
        cc -std=c99 -O2 -o /tmp/libbitcoinpqc-host-smoke /tmp/libbitcoinpqc-host-smoke.c \
          -Iinclude \
          build/lib/libbitcoinpqc.a \
          build/lib/libsecp256k1.a \
          -lpthread -lm
        /tmp/libbitcoinpqc-host-smoke
      '
    else
      echo "ctest/cc not found and nix not available" >&2
      exit 1
    fi

# Host path only.
local: cmake-test

# ── Housekeeping ─────────────────────────────────────────────────────────────

# Remove local build dir and Nix result links.
clean:
    rm -rf build result result-*
