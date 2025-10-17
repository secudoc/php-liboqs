# Changelog

All notable changes to this project will be documented in this file.
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
