# OQS Wrapper Extension

A minimal PHP extension wrapping [liboqs](https://openquantumsafe.org/liboqs/) KEM and signature
APIs into a namespaced API suitable for the [SecuDoc](https://www.secudoc.nl/) stack. The runtime namespace, configure flag,
and module name are **`OQS`** (extension: `oqs.so`).

> Note on naming: NIST standardized Kyber as **ML-KEM** (FIPS 203). liboqs exposes both names
> (`Kyber{512,768,1024}` and `ML-KEM-{512,768,1024}`) depending on build options. This extension
> accepts whatever your liboqs provides.

Once PHP natively supports PQC, this wrapper will likely be deprecated.

---
## API

### KEM

`OQS\KEM` exposes post-quantum key encapsulation:

- `OQS\KEM::algorithms(): string[]` — list enabled KEM identifiers.
- `OQS\KEM::keypair(string $algorithm): array{0: string $publicKey, 1: string $secretKey}`
- `OQS\KEM::encapsulate(string $algorithm, string $publicKey): array{0: string $ciphertext, 1: string $sharedSecret}`
- `OQS\KEM::decapsulate(string $algorithm, string $ciphertext, string $secretKey): string`

All algorithm identifiers surfaced by liboqs are also available as class constants, e.g.
`OQS\KEM::ALG_KYBER768` and/or `OQS\KEM::ALG_ML_KEM_768` (depending on your liboqs build).

> **Binary outputs**: All keys, ciphertexts, and shared secrets are raw binary strings. Base64-encode
> if you need printable or JSON-safe values.

### Signatures

`OQS\Signature` wraps stateless PQ signatures:

- `OQS\Signature::algorithms(): string[]`
- `OQS\Signature::keypair(string $algorithm): array{0: string $publicKey, 1: string $secretKey}`
- `OQS\Signature::sign(string $algorithm, string $message, string $secretKey): string`
- `OQS\Signature::verify(string $algorithm, string $message, string $signature, string $publicKey): bool`

Signature identifiers are also class constants, e.g. `OQS\Signature::ALG_DILITHIUM_3`.

Global namespace constants (e.g. `OQS\VERSION_TEXT`) mirror liboqs build info.

---

## Quick start (usage)

```php
<?php
use OQS\KEM;

// Pick an algorithm supported by your liboqs build:
$alg = defined('OQS\\KEM::ALG_ML_KEM_768') ? OQS\KEM::ALG_ML_KEM_768 : OQS\KEM::ALG_KYBER768;

[$pk, $sk] = KEM::keypair($alg);
[$ct, $ss1] = KEM::encapsulate($alg, $pk);
$ss2 = KEM::decapsulate($alg, $ct, $sk);

assert(hash_equals($ss1, $ss2));

// If you need text-safe values:
echo base64_encode($ct), "\n", base64_encode($ss1), "\n";
```

---

## Installing liboqs

Before building this PHP extension, you need the **liboqs** C library and headers installed on your system.  
You can either build it from source or install it via a package manager if available.

### Build from source (recommended)
```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_BUILD_ONLY_LIB=ON ..
make -j$(nproc)
sudo make install
```
This installs `liboqs.so` to `/usr/local/lib` and headers to `/usr/local/include/oqs`.

### Verify installation
```bash
pkg-config --modversion liboqs
# should report 0.14.0 or newer
```

Then proceed with the build steps below.

---

## Requirements

- PHP dev tools (`phpize`, `php-config`, headers)
- `liboqs` **0.14.0 or newer** (headers under `include/oqs`, libs under `lib`)
- A compiler toolchain (gcc/clang, make, autoconf)

Check your liboqs version:
```bash
pkg-config --modversion liboqs
# or:
grep -E 'OQS_VERSION_(TEXT|MAJOR|MINOR|PATCH)' /usr/local/include/oqs/oqsconfig.h
```

---

## Build & install

### Using `pkg-config` (recommended)

```bash
/php/bin/phpize
./configure --with-php-config=/php/bin/php-config
make -j$(nproc)
sudo make install
echo "extension=oqs.so" | sudo tee /etc/php/<ver>/mods-available/oqs.ini
sudo phpenmod oqs
php -m | grep oqs
```

### Using an explicit liboqs prefix

If liboqs isn’t in pkg-config, pass the prefix that contains `include/oqs` and `lib/`:

```bash
/php/php-8.4/bin/phpize
./configure --with-php-config=/php/php-8.4/bin/php-config --with-oqs=/usr/local
make -j$(nproc) && sudo make install
```

---

## Troubleshooting

- **`liboqs 0.14.0 or newer is required`**  
  Ensure pkg-config finds liboqs ≥ 0.14.0 (`pkg-config --modversion liboqs`) **or** your
  `--with-oqs` prefix points to headers with `oqs/oqsconfig.h` reporting ≥ 0.14.0.

- **`oqs.h not found`**  
  Your `--with-oqs=/prefix` must contain `/prefix/include/oqs/oqs.h` and `/prefix/lib/liboqs.*`.

- **Runtime loader can’t find `liboqs.so`**  
  Either install liboqs to a standard location (e.g. `/usr/local`) or set:
  ```bash
  export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH    # Linux
  export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH # macOS (disable SIP for non-system paths)
  ```

- **Which algorithms are enabled?**
  ```php
  print_r(OQS\KEM::algorithms());
  print_r(OQS\Signature::algorithms());
  ```

---

## Notes

- Algorithms and sizes are defined by liboqs at build time. If an identifier isn’t present in
  `OQS\KEM::algorithms()`, your liboqs was built without it.
- Thread safety: the extension itself is stateless; use a thread-safe PHP build (ZTS) if your SAPI
  requires it.
---

## Disclaimer

This extension is provided **as-is** without any warranty. It is intended for experimentation,
prototyping, and research purposes only. Do **not** use this software in production environments
that require certified or audited cryptographic implementations. The liboqs library itself is
not a FIPS-validated module, and the PHP wrapper has not been security reviewed. Use entirely
at your own risk.
