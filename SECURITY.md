# Security

## Reporting a vulnerability

Email security@surmount.systems. Do not open a public issue for a problem that is not already public. Say which revision, which algorithm, and what you observed.

## Scope

This C library's key generation, signing, and verification for secp256k1 Schnorr, ML-DSA-44, and SLH-DSA-SHA2-128s are in scope. The bindings repository is out of scope. The code is reference code. The algorithms are specified by FIPS 204 and FIPS 205. This library is not a certified module.

## Supported revisions

There is no release series. Revision 053e954534b13c1dbdc8ef4f9ae4d93bb301bab6 does not verify OpenSSL SLH-DSA-SHA2-128s pure-mode signatures. A tree that contains the pure-mode prefix and the FIPS 205 FORS index line does, as locked by tests/slh_dsa_sha2_openssl.c.

## SLH-DSA on 053e954

The public discussion is https://github.com/cryptoquick/libbitcoinpqc/issues/32.

Revision 053e954534b13c1dbdc8ef4f9ae4d93bb301bab6 is origin/main and the parent of 07b227d. It fails OpenSSL SLH-DSA-SHA2-128s pure-mode verification for two reasons. It signs and verifies the raw message, so the pure-mode prefix is absent. Its message_to_indices function uses the SPHINCS+ 3.1 order, (offset & 0x7) placed with << j, instead of the FIPS 205 FORS bit order.

Pure mode with an empty context prefixes the message with 0x00 || 0x00. Pre-hash and a caller context are not offered.

The reproduction links this tree's driver, tests/slh_dsa_sha2_openssl.c, to that revision's installed library. The driver calls bitcoin_pqc_verify only. Build it with this command:

```
nix build ./repro#checks.x86_64-linux.slh-dsa-main-rejects-openssl
```

For each valid signature the driver prints got -3 expected 0. got -3 is BITCOIN_PQC_ERROR_BAD_SIGNATURE. expected 0 is BITCOIN_PQC_OK. Those two lines are the proof. A non-zero exit alone is not the proof.

A FIPS 205 verifier and that pre-fix library do not accept each other's SLH-DSA signatures. The recorded failure is rejection of a valid signature, not acceptance of a forged one. ML-DSA-44 on the fixed tree matched all seven OpenSSL cases with no product change. Separate builds that drop only the prefix or only the FORS line were not run. The repro proves the pre-fix revision as a whole. The maintainer said on 2026-11-26 that the library is not deployed so far as they know.

## Entropy and deterministic signatures

Callers supply entropy. The README requires 128 bytes of entropy for key generation. See docs/user_provided_entropy.md. Signing does not draw fresh randomness. slh_dsa_derandomize hashes the raw message. That domain byte is not the FIPS prefix. Do not expect byte-identical signatures from an OpenSSL hedged signer.

## Already public

Issue 32 and this reproduction are public. There is no embargo on that finding.
