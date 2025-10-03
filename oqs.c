#include "php_oqs.h"
#include <ctype.h>
#include <string.h>

#include "Zend/zend_exceptions.h"
#include "ext/standard/info.h"

/* ---------- Utilities ---------- */

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

        char constant_name[128];
        size_t j = 0;
        const char *prefix = "ALG_";
        while (*prefix && j < sizeof(constant_name) - 1) {
            constant_name[j++] = *prefix++;
        }

        for (const char *p = identifier; *p && j < sizeof(constant_name) - 1; ++p) {
            if (isalnum((unsigned char)*p)) {
                constant_name[j++] = (char)toupper((unsigned char)*p);
            } else {
                constant_name[j++] = '_';
            }
        }

        constant_name[j] = '\0';

        zend_declare_class_constant_stringl(ce, constant_name, j, identifier, strlen(identifier));
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

static zend_class_entry *oqs_kem_ce;
static zend_class_entry *oqs_signature_ce;

static zend_always_inline void throw_unsupported_algorithm(void)
{
    zend_throw_exception(zend_ce_exception, "Algorithm not supported by liboqs", 0);
}

static zend_always_inline void throw_failure(const char *message)
{
    zend_throw_exception(zend_ce_exception, message, 0);
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
        throw_unsupported_algorithm();
        RETURN_THROWS();
    }

    unsigned char *pk = (unsigned char*)emalloc(kem->length_public_key);
    unsigned char *sk = (unsigned char*)emalloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        OQS_MEM_cleanse(pk, kem->length_public_key);
        OQS_MEM_cleanse(sk, kem->length_secret_key);
        efree(pk); efree(sk);
        OQS_KEM_free(kem);
        throw_failure("Keypair generation failed");
        RETURN_THROWS();
    }

    array_init_size(return_value, 2);
    add_next_index_stringl(return_value, (char*)pk, kem->length_public_key);
    add_next_index_stringl(return_value, (char*)sk, kem->length_secret_key);

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
        throw_unsupported_algorithm();
        RETURN_THROWS();
    }

    if (pk_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        throw_failure("Invalid public key length for selected algorithm");
        RETURN_THROWS();
    }

    unsigned char *ct = (unsigned char*)emalloc(kem->length_ciphertext);
    unsigned char *ss = (unsigned char*)emalloc(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ct, ss, (const unsigned char*)public_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(ct, kem->length_ciphertext);
        OQS_MEM_cleanse(ss, kem->length_shared_secret);
        efree(ct); efree(ss);
        OQS_KEM_free(kem);
        throw_failure("Encapsulation failed");
        RETURN_THROWS();
    }

    array_init_size(return_value, 2);
    add_next_index_stringl(return_value, (char*)ct, kem->length_ciphertext);
    add_next_index_stringl(return_value, (char*)ss, kem->length_shared_secret);

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
        throw_unsupported_algorithm();
        RETURN_THROWS();
    }

    if (ct_len != kem->length_ciphertext || sk_len != kem->length_secret_key) {
        OQS_KEM_free(kem);
        throw_failure("Invalid ciphertext or secret key length for selected algorithm");
        RETURN_THROWS();
    }

    unsigned char *ss = (unsigned char*)emalloc(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, ss,
        (const unsigned char*)ciphertext, (const unsigned char*)secret_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(ss, kem->length_shared_secret);
        efree(ss);
        OQS_KEM_free(kem);
        throw_failure("Decapsulation failed");
        RETURN_THROWS();
    }

    RETVAL_STRINGL((char*)ss, kem->length_shared_secret);

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
        (size_t (*)(void))OQS_KEM_alg_count,
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
        throw_unsupported_algorithm();
        RETURN_THROWS();
    }

    unsigned char *public_key = (unsigned char*)emalloc(sig->length_public_key);
    unsigned char *secret_key = (unsigned char*)emalloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(public_key, sig->length_public_key);
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        efree(public_key); efree(secret_key);
        OQS_SIG_free(sig);
        throw_failure("Keypair generation failed");
        RETURN_THROWS();
    }

    array_init_size(return_value, 2);
    add_next_index_stringl(return_value, (char*)public_key, sig->length_public_key);
    add_next_index_stringl(return_value, (char*)secret_key, sig->length_secret_key);

    OQS_MEM_cleanse(public_key, sig->length_public_key);
    OQS_MEM_cleanse(secret_key, sig->length_secret_key);
    efree(public_key); efree(secret_key);
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
        throw_unsupported_algorithm();
        RETURN_THROWS();
    }

    if (secret_len != sig->length_secret_key) {
        OQS_SIG_free(sig);
        throw_failure("Invalid secret key length for selected algorithm");
        RETURN_THROWS();
    }

    size_t allocated_len = sig->length_signature;
    size_t signature_len = allocated_len;
    unsigned char *signature = (unsigned char*)emalloc(allocated_len);

    if (OQS_SIG_sign(sig, signature, &signature_len,
            (const unsigned char*)message, message_len,
            (const unsigned char*)secret_key) != OQS_SUCCESS) {
        OQS_MEM_cleanse(signature, allocated_len);
        efree(signature);
        OQS_SIG_free(sig);
        throw_failure("Signing failed");
        RETURN_THROWS();
    }

    RETVAL_STRINGL((char*)signature, signature_len);

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
        throw_unsupported_algorithm();
        RETURN_THROWS();
    }

    if (public_len != sig->length_public_key || signature_len > sig->length_signature) {
        OQS_SIG_free(sig);
        throw_failure("Invalid signature or public key length for selected algorithm");
        RETURN_THROWS();
    }

    OQS_STATUS status = OQS_SIG_verify(sig,
        (const unsigned char*)message, message_len,
        (const unsigned char*)signature, signature_len,
        (const unsigned char*)public_key);

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
        (size_t (*)(void))OQS_SIG_alg_count,
        OQS_SIG_alg_identifier);
}

/* ---------- Arginfo ---------- */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_keypair, 0, 1, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_KEM_encapsulate, 0, 2, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, algorithm, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
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

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Signature_algorithms, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

/* ---------- Methods table ---------- */

static const zend_function_entry kem_methods[] = {
    PHP_ME(KEM, keypair,     arginfo_KEM_keypair,     ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, encapsulate, arginfo_KEM_encapsulate, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, decapsulate, arginfo_KEM_decapsulate, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(KEM, algorithms,  arginfo_KEM_algorithms,  ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};

static const zend_function_entry signature_methods[] = {
    PHP_ME(Signature, keypair,     arginfo_Signature_keypair,     ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, sign,        arginfo_Signature_sign,        ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, verify,      arginfo_Signature_verify,      ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(Signature, algorithms,  arginfo_Signature_algorithms,  ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};

/* ---------- Module init ---------- */

static void register_kem_class(void)
{
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "OQS", "KEM", kem_methods);
    oqs_kem_ce = zend_register_internal_class(&ce);

    register_algorithm_constants(oqs_kem_ce,
        (size_t (*)(void))OQS_KEM_alg_count,
        OQS_KEM_alg_identifier);
}

static void register_signature_class(void)
{
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "OQS", "Signature", signature_methods);
    oqs_signature_ce = zend_register_internal_class(&ce);

    register_algorithm_constants(oqs_signature_ce,
        (size_t (*)(void))OQS_SIG_alg_count,
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
    REGISTER_NS_LONG_CONSTANT("OQS", "VERSION_NUMBER", (zend_long)OQS_VERSION_NUMBER, CONST_CS | CONST_PERSISTENT);
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