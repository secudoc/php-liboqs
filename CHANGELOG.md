# Changelog

All notable changes to this project will be documented in this file.

## [0.4.1] - 2026-04-18

### Added
- **`Signature::keypairDerand(string $algorithm, string $seed)`** — deterministic signature keypair generation from a caller-supplied seed.

### Why
Enables spec-conformant composite signature schemes (e.g. IETF draft-ietf-lamps-pq-composite-sigs-18 `id-MLDSA65-Ed25519-SHA512`) which store the 32-byte FIPS 204 ML-DSA seed `ξ` rather than the 4032-byte expanded secret key. Also makes NIST KAT verification possible directly from PHP.

### How
liboqs does not expose `OQS_SIG_keypair_derand` (as of 0.14.x). The extension
substitutes liboqs's `OQS_randombytes` callback with a seed-sourced one for
the duration of `OQS_SIG_keypair`, then restores the system RNG. For ML-DSA the
algorithm draws exactly its seed length from `randombytes` and derives all key
material deterministically, so this faithfully reproduces FIPS 204 §5.1 (ML-DSA.KeyGen).

Thread-safety: the swap is guarded by a pthread mutex. Required seed length is
algorithm-specific (ML-DSA: 32 bytes); an under-sized seed throws `OQS\Exception`.

## [0.4.0] - 2026-04-10

### Added
- **KEM deterministic operations** (wraps `OQS_KEM_keypair_derand` / `OQS_KEM_encaps_derand`):
    - `KEM::keypairDerand(string $algorithm, string $seed)` — deterministic keypair from seed
    - `KEM::encapsulateDerand(string $algorithm, string $publicKey, string $seed)` — deterministic encapsulation from seed
- **Context-aware signatures** (wraps `OQS_SIG_sign_with_ctx_str` / `OQS_SIG_verify_with_ctx_str`):
    - `Signature::signWithContext(string $algorithm, string $message, string $context, string $secretKey)`
    - `Signature::verifyWithContext(string $algorithm, string $message, string $signature, string $context, string $publicKey)`

### Why
- `keypairDerand` enables spec-conformant X-Wing KEM (IETF draft-connolly-cfrg-xwing-kem-10) which derives ML-KEM keys from a 32-byte seed via SHAKE256
- `encapsulateDerand` enables validation against IETF test vectors with deterministic randomness
- `signWithContext` / `verifyWithContext` enable context-bound PQC signatures for future sender authentication

## [0.3.3] - 2026-03-16
- Added PIE installation instructions
- Updated PHP 8.5 support
- 

## [0.3.2] - 2025-10-17
- Version bump

## [0.3.0] - 2025-10-17
- Added PIE / Packagist support (composer.json)
- Added liboqs installation instructions

## [0.2.0] - 2025-10-03

### Added
- **PHP 8+ Return Type Declarations** in arginfo:
    - `KEM::keypair` → array
    - `KEM::encapsulate` → array
    - `KEM::decapsulate` → string
    - `KEM::algorithms` → array
    - `Signature::keypair` → array
    - `Signature::sign` → string
    - `Signature::verify` → bool
    - `Signature::algorithms` → array
- Added stricter return type reflection.

### Changed
- Memory cleanse now uses **`OQS_MEM_cleanse`** from liboqs. This keeps memory-zeroing consistent with liboqs.

---

## [0.1.0] - 2025-10-01

### Added
- Initial release of the **OQS PHP extension** (`oqs.so`).
- Namespaced API under `OQS\KEM` and `OQS\Signature`.
- Implemented KEM primitives:
    - `keypair`, `encapsulate`, `decapsulate`, `algorithms`.
- Implemented signature primitives:
    - `keypair`, `sign`, `verify`, `algorithms`.
- Constants: algorithm identifiers, `OQS\VERSION_TEXT`, `OQS\KEM_DEFAULT`, etc.
- PHPT test suite covering key encapsulation and signatures.

---
