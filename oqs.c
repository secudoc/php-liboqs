#include "php_oqs.h"
#include <ctype.h>
#include <pthread.h>
#include <string.h>

#include "Zend/zend_exceptions.h"
#include "ext/standard/info.h"

/* ---------- Signature derandomization (see Signature::keypairDerand) ----------
 *
 * liboqs does not expose OQS_SIG_keypair_derand (as of 0.14.x), so we implement
 * deterministic signature keygen by temporarily replacing liboqs's randombytes
 * callback with one that streams bytes out of a caller-supplied seed buffer.
 * The algorithm internally draws its seed from OQS_randombytes() and then
 * derives all key material deterministically, so feeding the seed byte-for-byte
 * reproduces FIPS 204 §5.1 (ML-DSA.KeyGen) with our own ξ.
 *
 * Global state, but guarded by derand_rng_mutex so concurrent calls (under ZTS
 * or from signal handlers) serialize. Non-ZTS PHP is single-threaded per
 * request, but we lock unconditionally to stay correct in hybrid setups. */

static pthread_mutex_t derand_rng_mutex = PTHREAD_MUTEX_INITIALIZER;
static const unsigned char *derand_rng_seed = NULL;
static size_t derand_rng_seed_len = 0;
static size_t derand_rng_seed_pos = 0;
static int derand_rng_exhausted = 0;

static void derand_rng_callback(uint8_t *buffer, size_t bytes_to_read)
{
    if (derand_rng_seed_pos + bytes_to_read > derand_rng_seed_len) {
        /* Algorithm requested more randomness than the seed provides. Mark the
         * operation as exhausted; the wrapper turns this into a PHP exception
         * after OQS_SIG_keypair returns. Zero the buffer in the meantime so we
         * do not leak stack contents into the key material. */
        derand_rng_exhausted = 1;
        memset(buffer, 0, bytes_to_read);
        return;
    }
    memcpy(buffer, derand_rng_seed + derand_rng_seed_pos, bytes_to_read);
    derand_rng_seed_pos += bytes_to_read;
}

/* ---------- Utilities ---------- */

static zend_class_entry *oqs_kem_ce;
static zend_class_entry *oqs_signature_ce;
static zend_class_entry *oqs_exception_ce;

static void register_algorithm_constants(zend_class_entry *ce,
    size_t (*count_cb)(void),
    const char *(*identifier_cb)(size_t))
{
    if (!ce || !count_cb || !identifier_cb) {
        return;
    }

    size_t count = count_cb();
    for (size_t i = 0; i < count; ++i) {
        const char *identifier = identifier_cb(i);
        if (!identifier) {
            continue;
        }

        size_t identifier_len = strlen(identifier);
        size_t constant_len = sizeof("ALG_") - 1 + identifier_len;
        char *constant_name = emalloc(constant_len + 1);
        size_t j = 0;
        const char *prefix = "ALG_";

        while (*prefix) {
            constant_name[j++] = *prefix++;
        }

        for (const char *p = identifier; *p; ++p) {
            if (isalnum((unsigned char)*p)) {
                constant_name[j++] = (char) toupper((unsigned char) *p);
            } else {
                constant_name[j++] = '_';
            }
        }

        constant_name[j] = '\0';

        zend_declare_class_constant_stringl(ce, constant_name, j, identifier, identifier_len);
        efree(constant_name);
    }
}

static void list_algorithms(zval *return_value,
    size_t (*count_cb)(void),
    const char *(*identifier_cb)(size_t))
{
    if (!count_cb || !identifier_cb) {
        array_init(return_value);
        return;
    }

    size_t count = count_cb();
    array_init_size(return_value, count);
    for (size_t i = 0; i < count; ++i) {
        const char *identifier = identifier_cb(i);
        if (!identifier) {
            continue;
        }
        add_next_index_string(return_value, identifier);
    }
}

static zend_always_inline void throw_unsupported_algorithm(const char *type, const char *algorithm)
{
    zend_throw_exception_ex(
        oqs_exception_ce,
        0,
        "%s algorithm is not supported by liboqs: %s",
        type,
        algorithm ? algorithm : "(unknown)"
    );
}

static zend_always_inline void throw_failure(const char *message)
{
    zend_throw_exception(oqs_exception_ce, message, 0);
}

static zend_always_inline void throw_length_mismatch(const char *label, const char *algorithm, size_t expected, size_t actual)
{
    zend_throw_exception_ex(
        oqs_exception_ce,
        0,
        "Invalid %s length for algorithm %s: expected %zu bytes, got %zu bytes",
        label,
        algorithm ? algorithm : "(unknown)",
        expected,
        actual
    );
}

static zend_always_inline void add_binary_pair(zval *return_value,
    const char *first_key, const unsigned char *first_value, size_t first_len,
    const char *second_key, const unsigned char *second_value, size_t second_len)
{
    array_init_size(return_value, 4);

    add_next_index_stringl(return_value, (const char *) first_value, first_len);
    add_next_index_stringl(return_value, (const char *) second_value, second_len);
    add_assoc_stringl(return_value, first_key, (const char *) first_value, first_len);
    add_assoc_stringl(return_value, second_key, (const char *) second_value, second_len);
}

/* ---------- OQS\\KEM class ---------- */

PHP_METHOD(KEM, keypair)
{
    char *alg = NULL; size_t alg_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &alg, &alg_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        throw_unsupported_algorithm("KEM", alg);
        RETURN_THROWS();
    }

    unsigned char *pk = (unsigned char *) emalloc(kem->length_public_key);
    unsigned char *sk = (unsigned char *) emalloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        OQS_MEM_cleanse(pk, kem->length_public_key);
        OQS_MEM_cleanse(sk, kem->length_secret_key);
        efree(pk); efree(sk);
        OQS_KEM_free(kem);
        throw_failure("Keypair generation failed");
        RETURN_THROWS();
    }

    add_binary_pair(return_value,
        "publicKey", pk, kem->length_public_key,
        "secretKey", sk, kem->length_secret_key);

    OQS_MEM_cleanse(pk, kem->length_public_key);
    OQS_MEM_cleanse(sk, kem->length_secret_key);
    efree(pk); efree(sk);
    OQS_KEM_free(kem);
}

PHP_METHOD(KEM, keypairDerand)
{
    char *alg = NULL; size_t alg_len = 0;
    char *seed = NULL; size_t seed_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &alg, &alg_len, &seed, &seed_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        throw_unsupported_algorithm("KEM", alg);
        RETURN_THROWS();
    }

    unsigned char *pk = (unsigned char *) emalloc(kem->length_public_key);
    unsigned char *sk = (unsigned char *) emalloc(kem->length_secret_key);

    if (OQS_KEM_keypair_derand(kem, pk, sk, (const unsigned char *) seed) != OQS_SUCCESS) {
        OQS_MEM_cleanse(pk, kem->length_public_key);
        OQS_MEM_cleanse(sk, kem->length_secret_key);
        efree(pk); efree(sk);
        OQS_KEM_free(kem);
        throw_failure("Deterministic keypair generation failed");
        RETURN_THROWS();
    }

    add_binary_pair(return_value,
        "publicKey", pk, kem->length_public_key,
        "secretKey", sk, kem->length_secret_key);

    OQS_MEM_cleanse(pk, kem->length_public_key);
    OQS_MEM_cleanse(sk, kem->length_secret_key);
    efree(pk); efree(sk);
    OQS_KEM_free(kem);
}

PHP_METHOD(KEM, encapsulate)
{
    char *alg = NULL; size_t alg_len = 0;
    char *public_key = NULL; size_t pk_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &alg, &alg_len, &public_key, &pk_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        throw_unsupported_algorithm("KEM", alg);
        RETURN_THROWS();
    }

    if (pk_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        throw_length_mismatch("public key", alg, kem->length_public_key, pk_len);
        RETURN_THROWS();
    }

    unsigned char *ct = (unsigned char *) emalloc(kem->length_ciphertext);
    unsigned char *ss = (unsigned char *) emalloc(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ct, ss, (const unsigned char *) public_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(ct, kem->length_ciphertext);
        OQS_MEM_cleanse(ss, kem->length_shared_secret);
        efree(ct); efree(ss);
        OQS_KEM_free(kem);
        throw_failure("Encapsulation failed");
        RETURN_THROWS();
    }

    add_binary_pair(return_value,
        "ciphertext", ct, kem->length_ciphertext,
        "sharedSecret", ss, kem->length_shared_secret);

    OQS_MEM_cleanse(ct, kem->length_ciphertext);
    OQS_MEM_cleanse(ss, kem->length_shared_secret);
    efree(ct); efree(ss);
    OQS_KEM_free(kem);
}

PHP_METHOD(KEM, encapsulateDerand)
{
    char *alg = NULL; size_t alg_len = 0;
    char *public_key = NULL; size_t pk_len = 0;
    char *seed = NULL; size_t seed_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss",
        &alg, &alg_len, &public_key, &pk_len, &seed, &seed_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        throw_unsupported_algorithm("KEM", alg);
        RETURN_THROWS();
    }

    if (pk_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        throw_length_mismatch("public key", alg, kem->length_public_key, pk_len);
        RETURN_THROWS();
    }

    unsigned char *ct = (unsigned char *) emalloc(kem->length_ciphertext);
    unsigned char *ss = (unsigned char *) emalloc(kem->length_shared_secret);

    if (OQS_KEM_encaps_derand(kem, ct, ss,
        (const unsigned char *) public_key, (const unsigned char *) seed) != OQS_SUCCESS) {
        OQS_MEM_cleanse(ct, kem->length_ciphertext);
        OQS_MEM_cleanse(ss, kem->length_shared_secret);
        efree(ct); efree(ss);
        OQS_KEM_free(kem);
        throw_failure("Deterministic encapsulation failed");
        RETURN_THROWS();
    }

    add_binary_pair(return_value,
        "ciphertext", ct, kem->length_ciphertext,
        "sharedSecret", ss, kem->length_shared_secret);

    OQS_MEM_cleanse(ct, kem->length_ciphertext);
    OQS_MEM_cleanse(ss, kem->length_shared_secret);
    efree(ct); efree(ss);
    OQS_KEM_free(kem);
}

PHP_METHOD(KEM, decapsulate)
{
    char *alg = NULL; size_t alg_len = 0;
    char *ciphertext = NULL; size_t ct_len = 0;
    char *secret_key = NULL; size_t sk_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss",
        &alg, &alg_len, &ciphertext, &ct_len, &secret_key, &sk_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        throw_unsupported_algorithm("KEM", alg);
        RETURN_THROWS();
    }

    if (ct_len != kem->length_ciphertext) {
        OQS_KEM_free(kem);
        throw_length_mismatch("ciphertext", alg, kem->length_ciphertext, ct_len);
        RETURN_THROWS();
    }

    if (sk_len != kem->length_secret_key) {
        OQS_KEM_free(kem);
        throw_length_mismatch("secret key", alg, kem->length_secret_key, sk_len);
        RETURN_THROWS();
    }

    unsigned char *ss = (unsigned char *) emalloc(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, ss,
        (const unsigned char *) ciphertext, (const unsigned char *) secret_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(ss, kem->length_shared_secret);
        efree(ss);
        OQS_KEM_free(kem);
        throw_failure("Decapsulation failed");
        RETURN_THROWS();
    }

    RETVAL_STRINGL((const char *) ss, kem->length_shared_secret);

    OQS_MEM_cleanse(ss, kem->length_shared_secret);
    efree(ss);
    OQS_KEM_free(kem);
}

PHP_METHOD(KEM, algorithms)
{
    if (zend_parse_parameters_none() == FAILURE) {
        RETURN_THROWS();
    }

    list_algorithms(return_value,
        (size_t (*)(void)) OQS_KEM_alg_count,
        OQS_KEM_alg_identifier);
}

/* ---------- OQS\\Signature class ---------- */

PHP_METHOD(Signature, keypair)
{
    char *alg = NULL; size_t alg_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &alg, &alg_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        throw_unsupported_algorithm("Signature", alg);
        RETURN_THROWS();
    }

    unsigned char *pk = (unsigned char *) emalloc(sig->length_public_key);
    unsigned char *sk = (unsigned char *) emalloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        OQS_MEM_cleanse(pk, sig->length_public_key);
        OQS_MEM_cleanse(sk, sig->length_secret_key);
        efree(pk); efree(sk);
        OQS_SIG_free(sig);
        throw_failure("Signature keypair generation failed");
        RETURN_THROWS();
    }

    add_binary_pair(return_value,
        "publicKey", pk, sig->length_public_key,
        "secretKey", sk, sig->length_secret_key);

    OQS_MEM_cleanse(pk, sig->length_public_key);
    OQS_MEM_cleanse(sk, sig->length_secret_key);
    efree(pk); efree(sk);
    OQS_SIG_free(sig);
}

PHP_METHOD(Signature, keypairDerand)
{
    char *alg = NULL; size_t alg_len = 0;
    char *seed = NULL; size_t seed_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &alg, &alg_len, &seed, &seed_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        throw_unsupported_algorithm("Signature", alg);
        RETURN_THROWS();
    }

    unsigned char *pk = (unsigned char *) emalloc(sig->length_public_key);
    unsigned char *sk = (unsigned char *) emalloc(sig->length_secret_key);

    pthread_mutex_lock(&derand_rng_mutex);

    derand_rng_seed = (const unsigned char *) seed;
    derand_rng_seed_len = seed_len;
    derand_rng_seed_pos = 0;
    derand_rng_exhausted = 0;

    OQS_randombytes_custom_algorithm(derand_rng_callback);
    OQS_STATUS status = OQS_SIG_keypair(sig, pk, sk);
    int exhausted = derand_rng_exhausted;
    size_t consumed = derand_rng_seed_pos;

    /* Restore the default RNG so subsequent liboqs calls (including later
     * invocations of keypair/encapsulate) use real entropy again. */
    OQS_randombytes_switch_algorithm("system");

    derand_rng_seed = NULL;
    derand_rng_seed_len = 0;
    derand_rng_seed_pos = 0;
    derand_rng_exhausted = 0;

    pthread_mutex_unlock(&derand_rng_mutex);

    if (status != OQS_SUCCESS || exhausted) {
        OQS_MEM_cleanse(pk, sig->length_public_key);
        OQS_MEM_cleanse(sk, sig->length_secret_key);
        efree(pk); efree(sk);
        OQS_SIG_free(sig);

        if (exhausted) {
            zend_throw_exception_ex(
                oqs_exception_ce,
                0,
                "Seed too short for algorithm %s: consumed %zu bytes, only %zu provided",
                alg,
                consumed,
                seed_len
            );
        } else {
            throw_failure("Deterministic signature keypair generation failed");
        }
        RETURN_THROWS();
    }

    add_binary_pair(return_value,
        "publicKey", pk, sig->length_public_key,
        "secretKey", sk, sig->length_secret_key);

    OQS_MEM_cleanse(pk, sig->length_public_key);
    OQS_MEM_cleanse(sk, sig->length_secret_key);
    efree(pk); efree(sk);
    OQS_SIG_free(sig);
}

PHP_METHOD(Signature, sign)
{
    char *alg = NULL; size_t alg_len = 0;
    char *message = NULL; size_t message_len = 0;
    char *secret_key = NULL; size_t secret_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss",
        &alg, &alg_len, &message, &message_len, &secret_key, &secret_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        throw_unsupported_algorithm("Signature", alg);
        RETURN_THROWS();
    }

    if (secret_len != sig->length_secret_key) {
        OQS_SIG_free(sig);
        throw_length_mismatch("secret key", alg, sig->length_secret_key, secret_len);
        RETURN_THROWS();
    }

    size_t allocated_len = sig->length_signature;
    size_t signature_len = allocated_len;
    unsigned char *signature = (unsigned char *) emalloc(allocated_len);

    if (OQS_SIG_sign(sig, signature, &signature_len,
            (const unsigned char *) message, message_len,
            (const unsigned char *) secret_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(signature, allocated_len);
        efree(signature);
        OQS_SIG_free(sig);
        throw_failure("Signing failed");
        RETURN_THROWS();
    }

    RETVAL_STRINGL((const char *) signature, signature_len);

    OQS_MEM_cleanse(signature, allocated_len);
    efree(signature);
    OQS_SIG_free(sig);
}

PHP_METHOD(Signature, verify)
{
    char *alg = NULL; size_t alg_len = 0;
    char *message = NULL; size_t message_len = 0;
    char *signature = NULL; size_t signature_len = 0;
    char *public_key = NULL; size_t public_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssss",
        &alg, &alg_len, &message, &message_len, &signature, &signature_len,
        &public_key, &public_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        throw_unsupported_algorithm("Signature", alg);
        RETURN_THROWS();
    }

    if (public_len != sig->length_public_key) {
        OQS_SIG_free(sig);
        throw_length_mismatch("public key", alg, sig->length_public_key, public_len);
        RETURN_THROWS();
    }

    if (signature_len > sig->length_signature) {
        OQS_SIG_free(sig);
        zend_throw_exception_ex(
            oqs_exception_ce,
            0,
            "Invalid signature length for algorithm %s: maximum %zu bytes, got %zu bytes",
            alg,
            sig->length_signature,
            signature_len
        );
        RETURN_THROWS();
    }

    OQS_STATUS status = OQS_SIG_verify(sig,
        (const unsigned char *) message, message_len,
        (const unsigned char *) signature, signature_len,
        (const unsigned char *) public_key);

    OQS_SIG_free(sig);

    if (status != OQS_SUCCESS) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(Signature, signWithContext)
{
    char *alg = NULL; size_t alg_len = 0;
    char *message = NULL; size_t message_len = 0;
    char *ctx_str = NULL; size_t ctx_len = 0;
    char *secret_key = NULL; size_t secret_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssss",
        &alg, &alg_len, &message, &message_len, &ctx_str, &ctx_len,
        &secret_key, &secret_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        throw_unsupported_algorithm("Signature", alg);
        RETURN_THROWS();
    }

    if (secret_len != sig->length_secret_key) {
        OQS_SIG_free(sig);
        throw_length_mismatch("secret key", alg, sig->length_secret_key, secret_len);
        RETURN_THROWS();
    }

    size_t allocated_len = sig->length_signature;
    size_t signature_len = allocated_len;
    unsigned char *signature = (unsigned char *) emalloc(allocated_len);

    if (OQS_SIG_sign_with_ctx_str(sig, signature, &signature_len,
            (const unsigned char *) message, message_len,
            (const unsigned char *) ctx_str, ctx_len,
            (const unsigned char *) secret_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(signature, allocated_len);
        efree(signature);
        OQS_SIG_free(sig);
        throw_failure("Signing with context failed");
        RETURN_THROWS();
    }

    RETVAL_STRINGL((const char *) signature, signature_len);

    OQS_MEM_cleanse(signature, allocated_len);
    efree(signature);
    OQS_SIG_free(sig);
}

PHP_METHOD(Signature, verifyWithContext)
{
    char *alg = NULL; size_t alg_len = 0;
    char *message = NULL; size_t message_len = 0;
    char *signature = NULL; size_t signature_len = 0;
    char *ctx_str = NULL; size_t ctx_len = 0;
    char *public_key = NULL; size_t public_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sssss",
        &alg, &alg_len, &message, &message_len, &signature, &signature_len,
        &ctx_str, &ctx_len, &public_key, &public_len) == FAILURE) {
        RETURN_THROWS();
    }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        throw_unsupported_algorithm("Signature", alg);
        RETURN_THROWS();
    }

    if (public_len != sig->length_public_key) {
        OQS_SIG_free(sig);
        throw_length_mismatch("public key", alg, sig->length_public_key, public_len);
        RETURN_THROWS();
    }

    if (signature_len > sig->length_signature) {
        OQS_SIG_free(sig);
        zend_throw_exception_ex(
            oqs_exception_ce,
            0,
            "Invalid signature length for algorithm %s: maximum %zu bytes, got %zu bytes",
            alg,
            sig->length_signature,
            signature_len
        );
        RETURN_THROWS();
    }

    OQS_STATUS status = OQS_SIG_verify_with_ctx_str(sig,
        (const unsigned char *) message, message_len,
        (const unsigned char *) signature, signature_len,
        (const unsigned char *) ctx_str, ctx_len,
        (const unsigned char *) public_key);

    OQS_SIG_free(sig);

    if (status != OQS_SUCCESS) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(Signature, algorithms)
{
    if (zend_parse_parameters_none() == FAILURE) {
        RETURN_THROWS();
    }

    list_algorithms(return_value,
        (size_t (*)(void)) OQS_SIG_alg_count,
        OQS_SIG_alg_identifier);
}

/* ---------- Arginfo ---------- */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_keypair, 0, 1, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_keypairDerand, 0, 2, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_encapsulate, 0, 2, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_encapsulateDerand, 0, 3, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_decapsulate, 0, 3, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_algorithms, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_keypair, 0, 1, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_keypairDerand, 0, 2, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_sign, 0, 3, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_verify, 0, 4, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_signWithContext, 0, 4, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_verifyWithContext, 0, 5, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_algorithms, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

/* ---------- Methods table ---------- */

static const zend_function_entry kem_methods[] = {
    PHP_ME(KEM, keypair,           arginfo_KEM_keypair,           ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, keypairDerand,     arginfo_KEM_keypairDerand,     ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, encapsulate,       arginfo_KEM_encapsulate,       ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, encapsulateDerand, arginfo_KEM_encapsulateDerand, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, decapsulate,       arginfo_KEM_decapsulate,       ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, algorithms,        arginfo_KEM_algorithms,        ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};

static const zend_function_entry signature_methods[] = {
    PHP_ME(Signature, keypair,           arginfo_Signature_keypair,           ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, keypairDerand,     arginfo_Signature_keypairDerand,     ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, sign,              arginfo_Signature_sign,              ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, signWithContext,    arginfo_Signature_signWithContext,   ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, verify,            arginfo_Signature_verify,            ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, verifyWithContext,  arginfo_Signature_verifyWithContext, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, algorithms,        arginfo_Signature_algorithms,        ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};

/* ---------- Module init ---------- */

static void register_exception_class(void)
{
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "OQS", "Exception", NULL);
    oqs_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);
}

static void register_kem_class(void)
{
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "OQS", "KEM", kem_methods);
    oqs_kem_ce = zend_register_internal_class(&ce);

    register_algorithm_constants(oqs_kem_ce,
        (size_t (*)(void)) OQS_KEM_alg_count,
        OQS_KEM_alg_identifier);
}

static void register_signature_class(void)
{
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "OQS", "Signature", signature_methods);
    oqs_signature_ce = zend_register_internal_class(&ce);

    register_algorithm_constants(oqs_signature_ce,
        (size_t (*)(void)) OQS_SIG_alg_count,
        OQS_SIG_alg_identifier);
}

PHP_MINIT_FUNCTION(oqs)
{
#if defined(OQS_VERSION_NUMBER)
    if (OQS_VERSION_NUMBER < 0x000E00) {
        php_error_docref(NULL, E_WARNING,
            "liboqs version 0.14.0 or newer is required; detected version number 0x%06x",
            (unsigned int) OQS_VERSION_NUMBER);
        return FAILURE;
    }
#endif

    register_exception_class();
    register_kem_class();
    register_signature_class();

#ifdef OQS_VERSION_TEXT
    REGISTER_NS_STRING_CONSTANT("OQS", "VERSION_TEXT", OQS_VERSION_TEXT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef OQS_VERSION_BUILD
    REGISTER_NS_STRING_CONSTANT("OQS", "VERSION_BUILD", OQS_VERSION_BUILD, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef OQS_COMMIT
    REGISTER_NS_STRING_CONSTANT("OQS", "COMMIT", OQS_COMMIT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef OQS_VERSION_NUMBER
    REGISTER_NS_LONG_CONSTANT("OQS", "VERSION_NUMBER", (zend_long) OQS_VERSION_NUMBER, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_NS_STRING_CONSTANT("OQS", "EXTENSION_VERSION", OQS_EXTENSION_VERSION, CONST_CS | CONST_PERSISTENT);

#ifdef OQS_KEM_alg_default
    REGISTER_NS_STRING_CONSTANT("OQS", "KEM_DEFAULT", OQS_KEM_alg_default, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef OQS_SIG_alg_default
    REGISTER_NS_STRING_CONSTANT("OQS", "SIGNATURE_DEFAULT", OQS_SIG_alg_default, CONST_CS | CONST_PERSISTENT);
#endif

    return SUCCESS;
}

PHP_MINFO_FUNCTION(oqs)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "oqs", "enabled");
#ifdef OQS_VERSION_TEXT
    php_info_print_table_row(2, "liboqs", OQS_VERSION_TEXT);
#endif
    php_info_print_table_row(2, "extension version", OQS_EXTENSION_VERSION);
    php_info_print_table_row(2, "Bug reports", "https://github.com/secudoc/php-liboqs/issues");
    php_info_print_table_row(2, "Maintainer", "wim@secudoc.nl");
    php_info_print_table_end();
}

zend_module_entry oqs_module_entry = {
    STANDARD_MODULE_HEADER,
    OQS_EXTENSION_NAME,
    NULL,
    PHP_MINIT(oqs),
    NULL,
    NULL,
    NULL,
    PHP_MINFO(oqs),
    OQS_EXTENSION_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OQS
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(oqs)
#endif
