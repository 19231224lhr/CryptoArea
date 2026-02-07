# Wallet Crypto Refactor Plan

## Goal
Turn `crypto-suites` into a wallet-facing crypto library that exposes stable APIs for:
- private/public key generation
- address generation
- post-quantum signature and verification
- foundational wallet crypto helpers

## Scope
This plan treats the repository as two capability layers:
- `pqcgo`: post-quantum signing engine and wrappers
- `crypto`: classical signature/hash primitives

The wallet integration layer will be built incrementally, starting from `pqcgo` high-level APIs and then unifying both modules behind one stable facade.

## Phase 1 (Implemented in this iteration)
1. Add wallet-oriented high-level APIs in `pqcgo`:
   - keypair generation (`GenerateKeyPair`, `GenerateKeyPairWithSeed`)
   - message sign/verify (`SignMessage`, `VerifyMessage`)
   - scheme parsing (`ParseSchemeName`)
2. Add address generation API in `pqcgo`:
   - deterministic pubkey-to-address flow
   - configurable output encoding (`hex`, `base58check`)
3. Add minimal wallet crypto helpers in `pqcgo`:
   - random bytes generation
   - `SHA-256`
   - `HMAC-SHA256`
   - public key fingerprint utility
4. Add minimal regression tests:
   - cgo path (full sign/verify flow)
   - !cgo path (graceful error propagation from stubs)

## Phase 2
1. Add KEM APIs into `pqcgo` (ML-KEM / AIGIS-ENC wrappers) for wallet E2E encryption scenarios.
2. Add deterministic keychain support for wallet use:
   - child-key derivation domain separation
   - derivation path format and validation
3. Add explicit key metadata model:
   - algorithm id
   - key version
   - serialization format

## Phase 3
1. Build unified wallet facade in `crypto` module that can route:
   - classical schemes (existing `crypto/signature`)
   - PQC schemes (`pqcgo`)
2. Add address profiles:
   - BTC-like (`hash160 + base58check`)
   - ETH-like (`keccak + hex`)
   - custom chain profile hooks
3. Add compatibility tests across modules and serialized vectors.

## Phase 4
1. Hardening and release readiness:
   - negative/fuzz tests on all public APIs
   - malformed input corpus tests
   - benchmark baselines by algorithm
2. API stability:
   - versioned exported types
   - migration notes and deprecation policy
3. CI matrix:
   - `CGO_ENABLED=0` and `CGO_ENABLED=1`
   - Windows/Linux build targets

## Design Defaults
- Keep existing low-level signatures unchanged for compatibility.
- New wallet APIs are additive and non-breaking.
- Prefer deterministic address derivation from public key bytes.
- In no-cgo environments, keep compile success and return explicit runtime errors.

## Acceptance Criteria
- Wallet callers can complete `keygen -> address -> sign -> verify` through a single high-level package in `pqcgo`.
- Invalid inputs return errors (no panic).
- `CGO_ENABLED=0` test path remains green with explicit "requires cgo" errors.
- Existing low-level APIs and tests remain compatible.
