#include <ruby.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "secure_db_fields_core.h"

#define SDF_SHA256_BLOCK_BYTES 64

static VALUE mSecureDBFields;
static VALUE mNative;
static VALUE eError;
static VALUE eAuthError;
static VALUE eFormatError;
static VALUE eKeyError;

typedef struct {
    SHA256_CTX inner0;
    SHA256_CTX outer0;
} rb_sdf_hmac_sha256_key;

static void rb_sdf_raise(sdf_status st, const char *err) {
    VALUE klass = eError;
    if (st == SDF_ERR_AUTH)
        klass = eAuthError;
    else if (st == SDF_ERR_FORMAT)
        klass = eFormatError;
    else if (st == SDF_ERR_KEY)
        klass = eKeyError;
    rb_raise(klass, "%s: %s", sdf_status_name(st), err && err[0] ? err : "unknown error");
}

static void rb_sdf_assert_array_lengths(VALUE values, VALUE aads) {
    Check_Type(values, T_ARRAY);
    Check_Type(aads, T_ARRAY);
    if (RARRAY_LEN(values) != RARRAY_LEN(aads))
        rb_raise(rb_eArgError, "values and aads must have the same length");
}

static void rb_sdf_assert_key_value(VALUE *key) {
    StringValue(*key);
    if (RSTRING_LEN(*key) != SDF_KEY_BYTES)
        rb_raise(eKeyError, "key_error: key must be exactly 32 bytes");
}

static uint32_t rb_sdf_key_id_from_value(VALUE key_id_value) {
    unsigned long id = NUM2ULONG(key_id_value);
    if (id == 0 || id > UINT32_MAX)
        rb_raise(rb_eArgError, "key_id must be between 1 and 2^32-1");
    return (uint32_t)id;
}

static void rb_sdf_hmac_key_init(rb_sdf_hmac_sha256_key *prepared, VALUE key) {
    size_t i;
    const unsigned char *key_ptr;
    unsigned char ipad[SDF_SHA256_BLOCK_BYTES];
    unsigned char opad[SDF_SHA256_BLOCK_BYTES];

    rb_sdf_assert_key_value(&key);
    key_ptr = (const unsigned char *)RSTRING_PTR(key);

    for (i = 0; i < SDF_SHA256_BLOCK_BYTES; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    for (i = 0; i < SDF_KEY_BYTES; i++) {
        ipad[i] ^= key_ptr[i];
        opad[i] ^= key_ptr[i];
    }

    if (SHA256_Init(&prepared->inner0) != 1 ||
        SHA256_Update(&prepared->inner0, ipad, SDF_SHA256_BLOCK_BYTES) != 1 ||
        SHA256_Init(&prepared->outer0) != 1 ||
        SHA256_Update(&prepared->outer0, opad, SDF_SHA256_BLOCK_BYTES) != 1) {
        sdf_secure_clear(ipad, sizeof(ipad));
        sdf_secure_clear(opad, sizeof(opad));
        rb_raise(eError, "crypto_failed: SHA256 init failed");
    }

    sdf_secure_clear(ipad, sizeof(ipad));
    sdf_secure_clear(opad, sizeof(opad));
}

static int rb_sdf_hmac_sha256_digest(const rb_sdf_hmac_sha256_key *prepared,
                                     const unsigned char *value, size_t value_len,
                                     unsigned char out[SDF_BIDX_BYTES]) {
    SHA256_CTX inner_ctx;
    SHA256_CTX outer_ctx;
    unsigned char inner[SDF_BIDX_BYTES];
    int ok;

    inner_ctx = prepared->inner0;
    outer_ctx = prepared->outer0;
    ok = (value_len == 0 || SHA256_Update(&inner_ctx, value, value_len) == 1) &&
         SHA256_Final(inner, &inner_ctx) == 1 &&
         SHA256_Update(&outer_ctx, inner, SDF_BIDX_BYTES) == 1 &&
         SHA256_Final(out, &outer_ctx) == 1;

    sdf_secure_clear(inner, sizeof(inner));
    sdf_secure_clear(&inner_ctx, sizeof(inner_ctx));
    sdf_secure_clear(&outer_ctx, sizeof(outer_ctx));
    return ok;
}

static VALUE rb_sdf_bidx_string(const unsigned char out[SDF_BIDX_BYTES]) {
    return rb_str_new((const char *)out, SDF_BIDX_BYTES);
}

static VALUE rb_sdf_version(VALUE self) {
    (void)self;
    return rb_str_new_cstr(SDF_VERSION);
}

static VALUE rb_sdf_encrypt(int argc, VALUE *argv, VALUE self) {
    VALUE plaintext, key, aad, key_id_value;
    char err[SDF_MAX_ERR];
    sdf_status st;
    uint32_t key_id = 1;
    size_t out_len = 0;
    size_t out_cap;
    VALUE result;
    (void)self;

    rb_scan_args(argc, argv, "31", &plaintext, &key, &aad, &key_id_value);
    StringValue(plaintext);
    rb_sdf_assert_key_value(&key);
    StringValue(aad);
    if (!NIL_P(key_id_value))
        key_id = rb_sdf_key_id_from_value(key_id_value);

    out_cap = sdf_encrypt_aes_256_gcm_output_len((size_t)RSTRING_LEN(plaintext));
    if (out_cap > (size_t)LONG_MAX)
        rb_raise(rb_eArgError, "plaintext too large");
    result = rb_str_new(NULL, (long)out_cap);

    st = sdf_encrypt_aes_256_gcm_into(
        (const unsigned char *)RSTRING_PTR(plaintext), (size_t)RSTRING_LEN(plaintext),
        (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
        (const unsigned char *)RSTRING_PTR(aad), (size_t)RSTRING_LEN(aad), key_id,
        (unsigned char *)RSTRING_PTR(result), out_cap, &out_len, err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
    if (out_len != out_cap)
        rb_str_resize(result, (long)out_len);
    return result;
}

static VALUE rb_sdf_decrypt(VALUE self, VALUE envelope, VALUE key, VALUE aad) {
    char err[SDF_MAX_ERR];
    sdf_status st;
    size_t out_cap;
    size_t out_len = 0;
    VALUE result;
    (void)self;

    StringValue(envelope);
    rb_sdf_assert_key_value(&key);
    StringValue(aad);

    out_cap = sdf_decrypt_aes_256_gcm_output_cap((const unsigned char *)RSTRING_PTR(envelope),
                                                 (size_t)RSTRING_LEN(envelope));
    if (out_cap == 0 && !sdf_is_valid_envelope((const unsigned char *)RSTRING_PTR(envelope),
                                               (size_t)RSTRING_LEN(envelope))) {
        rb_raise(eFormatError, "invalid_envelope: invalid MCEN envelope");
    }
    if (out_cap > (size_t)LONG_MAX)
        rb_raise(rb_eArgError, "ciphertext too large");

    result = rb_str_new(NULL, (long)out_cap);
    st = sdf_decrypt_aes_256_gcm_into(
        (const unsigned char *)RSTRING_PTR(envelope), (size_t)RSTRING_LEN(envelope),
        (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
        (const unsigned char *)RSTRING_PTR(aad), (size_t)RSTRING_LEN(aad),
        (unsigned char *)RSTRING_PTR(result), out_cap, &out_len, err, sizeof(err));
    if (st != SDF_OK) {
        if (out_cap > 0)
            sdf_secure_clear((void *)RSTRING_PTR(result), out_cap);
        rb_sdf_raise(st, err);
    }
    if (out_len != out_cap)
        rb_str_resize(result, (long)out_len);
    return result;
}

static VALUE rb_sdf_key_id(VALUE self, VALUE envelope) {
    uint32_t key_id = 0;
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(envelope);
    st = sdf_parse_key_id((const unsigned char *)RSTRING_PTR(envelope),
                          (size_t)RSTRING_LEN(envelope), &key_id, err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
    return UINT2NUM(key_id);
}

static VALUE rb_sdf_valid_envelope(VALUE self, VALUE envelope) {
    (void)self;
    StringValue(envelope);
    return sdf_is_valid_envelope((const unsigned char *)RSTRING_PTR(envelope),
                                 (size_t)RSTRING_LEN(envelope))
               ? Qtrue
               : Qfalse;
}

static VALUE rb_sdf_blind_index(VALUE self, VALUE value, VALUE key) {
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(value);
    rb_sdf_assert_key_value(&key);
    st = sdf_blind_index((const unsigned char *)RSTRING_PTR(value), (size_t)RSTRING_LEN(value),
                         (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key), out,
                         err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
    return rb_sdf_bidx_string(out);
}

static VALUE rb_sdf_e164_p(VALUE self, VALUE value) {
    (void)self;
    StringValue(value);
    return sdf_is_canonical_e164((const unsigned char *)RSTRING_PTR(value),
                                 (size_t)RSTRING_LEN(value))
               ? Qtrue
               : Qfalse;
}

static VALUE rb_sdf_phone_bidx(VALUE self, VALUE e164, VALUE key) {
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(e164);
    rb_sdf_assert_key_value(&key);
    st = sdf_phone_exact_bidx((const unsigned char *)RSTRING_PTR(e164), (size_t)RSTRING_LEN(e164),
                              (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
                              out, err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
    return rb_sdf_bidx_string(out);
}

static VALUE rb_sdf_phone_prefix_bidx(VALUE self, VALUE e164, VALUE prefix_digits_value,
                                      VALUE key) {
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    unsigned long prefix_digits;
    (void)self;
    StringValue(e164);
    rb_sdf_assert_key_value(&key);
    prefix_digits = NUM2ULONG(prefix_digits_value);
    if (prefix_digits == 0 || prefix_digits > 15)
        rb_raise(rb_eArgError, "prefix_digits must be between 1 and 15");
    st = sdf_phone_prefix_bidx((const unsigned char *)RSTRING_PTR(e164), (size_t)RSTRING_LEN(e164),
                               (unsigned int)prefix_digits, (const unsigned char *)RSTRING_PTR(key),
                               (size_t)RSTRING_LEN(key), out, err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
    return rb_sdf_bidx_string(out);
}

static void rb_sdf_assert_packed_len(long n) {
    if (n < 0 || n > LONG_MAX / SDF_BIDX_BYTES)
        rb_raise(rb_eArgError, "too many values for packed blind index output");
}

static VALUE rb_sdf_blind_index_many(VALUE self, VALUE values, VALUE key) {
    long i, n;
    VALUE result;
    rb_sdf_hmac_sha256_key prepared;
    unsigned char out[SDF_BIDX_BYTES];
    (void)self;

    Check_Type(values, T_ARRAY);
    rb_sdf_hmac_key_init(&prepared, key);
    n = RARRAY_LEN(values);
    result = rb_ary_new_capa(n);

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        StringValue(value);
        if (!rb_sdf_hmac_sha256_digest(&prepared, (const unsigned char *)RSTRING_PTR(value),
                                       (size_t)RSTRING_LEN(value), out)) {
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(eError, "crypto_failed: HMAC-SHA256 failed");
        }
        rb_ary_push(result, rb_sdf_bidx_string(out));
    }

    sdf_secure_clear(out, sizeof(out));
    sdf_secure_clear(&prepared, sizeof(prepared));
    return result;
}

static VALUE rb_sdf_blind_index_many_packed(VALUE self, VALUE values, VALUE key) {
    long i, n;
    VALUE result;
    rb_sdf_hmac_sha256_key prepared;
    unsigned char *dst;
    (void)self;

    Check_Type(values, T_ARRAY);
    rb_sdf_hmac_key_init(&prepared, key);
    n = RARRAY_LEN(values);
    rb_sdf_assert_packed_len(n);
    result = rb_str_new(NULL, n * SDF_BIDX_BYTES);
    dst = (unsigned char *)RSTRING_PTR(result);

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        StringValue(value);
        if (!rb_sdf_hmac_sha256_digest(&prepared, (const unsigned char *)RSTRING_PTR(value),
                                       (size_t)RSTRING_LEN(value), dst + (i * SDF_BIDX_BYTES))) {
            sdf_secure_clear(dst, (size_t)n * SDF_BIDX_BYTES);
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(eError, "crypto_failed: HMAC-SHA256 failed");
        }
    }

    sdf_secure_clear(&prepared, sizeof(prepared));
    return result;
}

static VALUE rb_sdf_phone_bidx_many(VALUE self, VALUE values, VALUE key) {
    long i, n;
    VALUE result;
    rb_sdf_hmac_sha256_key prepared;
    unsigned char out[SDF_BIDX_BYTES];
    (void)self;

    Check_Type(values, T_ARRAY);
    rb_sdf_hmac_key_init(&prepared, key);
    n = RARRAY_LEN(values);
    result = rb_ary_new_capa(n);

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        StringValue(value);
        if (!sdf_is_canonical_e164((const unsigned char *)RSTRING_PTR(value),
                                   (size_t)RSTRING_LEN(value))) {
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(rb_eArgError, "phone must be canonical E.164, e.g. +77771234567");
        }
        if (!rb_sdf_hmac_sha256_digest(&prepared, (const unsigned char *)RSTRING_PTR(value),
                                       (size_t)RSTRING_LEN(value), out)) {
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(eError, "crypto_failed: HMAC-SHA256 failed");
        }
        rb_ary_push(result, rb_sdf_bidx_string(out));
    }

    sdf_secure_clear(out, sizeof(out));
    sdf_secure_clear(&prepared, sizeof(prepared));
    return result;
}

static VALUE rb_sdf_phone_bidx_many_packed(VALUE self, VALUE values, VALUE key) {
    long i, n;
    VALUE result;
    rb_sdf_hmac_sha256_key prepared;
    unsigned char *dst;
    (void)self;

    Check_Type(values, T_ARRAY);
    rb_sdf_hmac_key_init(&prepared, key);
    n = RARRAY_LEN(values);
    rb_sdf_assert_packed_len(n);
    result = rb_str_new(NULL, n * SDF_BIDX_BYTES);
    dst = (unsigned char *)RSTRING_PTR(result);

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        StringValue(value);
        if (!sdf_is_canonical_e164((const unsigned char *)RSTRING_PTR(value),
                                   (size_t)RSTRING_LEN(value))) {
            sdf_secure_clear(dst, (size_t)n * SDF_BIDX_BYTES);
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(rb_eArgError, "phone must be canonical E.164, e.g. +77771234567");
        }
        if (!rb_sdf_hmac_sha256_digest(&prepared, (const unsigned char *)RSTRING_PTR(value),
                                       (size_t)RSTRING_LEN(value), dst + (i * SDF_BIDX_BYTES))) {
            sdf_secure_clear(dst, (size_t)n * SDF_BIDX_BYTES);
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(eError, "crypto_failed: HMAC-SHA256 failed");
        }
    }

    sdf_secure_clear(&prepared, sizeof(prepared));
    return result;
}

static VALUE rb_sdf_phone_prefix_bidx_many(VALUE self, VALUE values, VALUE prefix_digits_value,
                                           VALUE key) {
    long i, n;
    unsigned long prefix_digits;
    VALUE result;
    rb_sdf_hmac_sha256_key prepared;
    unsigned char out[SDF_BIDX_BYTES];
    (void)self;

    Check_Type(values, T_ARRAY);
    rb_sdf_hmac_key_init(&prepared, key);
    prefix_digits = NUM2ULONG(prefix_digits_value);
    if (prefix_digits == 0 || prefix_digits > 15)
        rb_raise(rb_eArgError, "prefix_digits must be between 1 and 15");

    n = RARRAY_LEN(values);
    result = rb_ary_new_capa(n);

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        size_t prefix_len;
        StringValue(value);
        if (!sdf_is_canonical_e164((const unsigned char *)RSTRING_PTR(value),
                                   (size_t)RSTRING_LEN(value))) {
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(rb_eArgError, "phone must be canonical E.164, e.g. +77771234567");
        }
        if ((size_t)prefix_digits > (size_t)RSTRING_LEN(value) - 1) {
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(rb_eArgError, "prefix_digits exceeds phone digit length");
        }
        prefix_len = (size_t)(1 + prefix_digits);
        if (!rb_sdf_hmac_sha256_digest(&prepared, (const unsigned char *)RSTRING_PTR(value),
                                       prefix_len, out)) {
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(eError, "crypto_failed: HMAC-SHA256 failed");
        }
        rb_ary_push(result, rb_sdf_bidx_string(out));
    }

    sdf_secure_clear(out, sizeof(out));
    sdf_secure_clear(&prepared, sizeof(prepared));
    return result;
}

static VALUE rb_sdf_phone_prefix_bidx_many_packed(VALUE self, VALUE values,
                                                  VALUE prefix_digits_value, VALUE key) {
    long i, n;
    unsigned long prefix_digits;
    VALUE result;
    rb_sdf_hmac_sha256_key prepared;
    unsigned char *dst;
    (void)self;

    Check_Type(values, T_ARRAY);
    rb_sdf_hmac_key_init(&prepared, key);
    prefix_digits = NUM2ULONG(prefix_digits_value);
    if (prefix_digits == 0 || prefix_digits > 15)
        rb_raise(rb_eArgError, "prefix_digits must be between 1 and 15");

    n = RARRAY_LEN(values);
    rb_sdf_assert_packed_len(n);
    result = rb_str_new(NULL, n * SDF_BIDX_BYTES);
    dst = (unsigned char *)RSTRING_PTR(result);

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        size_t prefix_len;
        StringValue(value);
        if (!sdf_is_canonical_e164((const unsigned char *)RSTRING_PTR(value),
                                   (size_t)RSTRING_LEN(value))) {
            sdf_secure_clear(dst, (size_t)n * SDF_BIDX_BYTES);
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(rb_eArgError, "phone must be canonical E.164, e.g. +77771234567");
        }
        if ((size_t)prefix_digits > (size_t)RSTRING_LEN(value) - 1) {
            sdf_secure_clear(dst, (size_t)n * SDF_BIDX_BYTES);
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(rb_eArgError, "prefix_digits exceeds phone digit length");
        }
        prefix_len = (size_t)(1 + prefix_digits);
        if (!rb_sdf_hmac_sha256_digest(&prepared, (const unsigned char *)RSTRING_PTR(value),
                                       prefix_len, dst + (i * SDF_BIDX_BYTES))) {
            sdf_secure_clear(dst, (size_t)n * SDF_BIDX_BYTES);
            sdf_secure_clear(&prepared, sizeof(prepared));
            rb_raise(eError, "crypto_failed: HMAC-SHA256 failed");
        }
    }

    sdf_secure_clear(&prepared, sizeof(prepared));
    return result;
}

static VALUE rb_sdf_encrypt_many(VALUE self, VALUE values, VALUE key, VALUE aads,
                                 VALUE key_id_value) {
    long i, n;
    VALUE result;
    uint32_t key_id;
    (void)self;

    rb_sdf_assert_array_lengths(values, aads);
    rb_sdf_assert_key_value(&key);
    key_id = rb_sdf_key_id_from_value(key_id_value);

    n = RARRAY_LEN(values);
    result = rb_ary_new_capa(n);
    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        VALUE aad = rb_ary_entry(aads, i);
        VALUE envelope;
        size_t out_cap;
        size_t out_len = 0;
        char err[SDF_MAX_ERR];
        sdf_status st;
        StringValue(value);
        StringValue(aad);
        out_cap = sdf_encrypt_aes_256_gcm_output_len((size_t)RSTRING_LEN(value));
        if (out_cap > (size_t)LONG_MAX)
            rb_raise(rb_eArgError, "plaintext too large");
        envelope = rb_str_new(NULL, (long)out_cap);
        st = sdf_encrypt_aes_256_gcm_into(
            (const unsigned char *)RSTRING_PTR(value), (size_t)RSTRING_LEN(value),
            (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
            (const unsigned char *)RSTRING_PTR(aad), (size_t)RSTRING_LEN(aad), key_id,
            (unsigned char *)RSTRING_PTR(envelope), out_cap, &out_len, err, sizeof(err));
        if (st != SDF_OK)
            rb_sdf_raise(st, err);
        if (out_len != out_cap)
            rb_str_resize(envelope, (long)out_len);
        rb_ary_push(result, envelope);
    }
    return result;
}

static VALUE rb_sdf_decrypt_many(VALUE self, VALUE envelopes, VALUE key, VALUE aads) {
    long i, n;
    VALUE result;
    (void)self;

    rb_sdf_assert_array_lengths(envelopes, aads);
    rb_sdf_assert_key_value(&key);

    n = RARRAY_LEN(envelopes);
    result = rb_ary_new_capa(n);
    for (i = 0; i < n; i++) {
        VALUE envelope = rb_ary_entry(envelopes, i);
        VALUE aad = rb_ary_entry(aads, i);
        VALUE plaintext;
        size_t out_cap;
        size_t out_len = 0;
        char err[SDF_MAX_ERR];
        sdf_status st;
        StringValue(envelope);
        StringValue(aad);
        out_cap = sdf_decrypt_aes_256_gcm_output_cap((const unsigned char *)RSTRING_PTR(envelope),
                                                     (size_t)RSTRING_LEN(envelope));
        if (out_cap == 0 && !sdf_is_valid_envelope((const unsigned char *)RSTRING_PTR(envelope),
                                                   (size_t)RSTRING_LEN(envelope))) {
            rb_raise(eFormatError, "invalid_envelope: invalid MCEN envelope");
        }
        if (out_cap > (size_t)LONG_MAX)
            rb_raise(rb_eArgError, "ciphertext too large");
        plaintext = rb_str_new(NULL, (long)out_cap);
        st = sdf_decrypt_aes_256_gcm_into(
            (const unsigned char *)RSTRING_PTR(envelope), (size_t)RSTRING_LEN(envelope),
            (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
            (const unsigned char *)RSTRING_PTR(aad), (size_t)RSTRING_LEN(aad),
            (unsigned char *)RSTRING_PTR(plaintext), out_cap, &out_len, err, sizeof(err));
        if (st != SDF_OK) {
            if (out_cap > 0)
                sdf_secure_clear((void *)RSTRING_PTR(plaintext), out_cap);
            rb_sdf_raise(st, err);
        }
        if (out_len != out_cap)
            rb_str_resize(plaintext, (long)out_len);
        rb_ary_push(result, plaintext);
    }
    return result;
}

static VALUE rb_sdf_hex_decode_key(VALUE self, VALUE hex) {
    unsigned char out[SDF_KEY_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(hex);
    st = sdf_hex_decode_32(StringValueCStr(hex), out, err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
    return rb_str_new((const char *)out, SDF_KEY_BYTES);
}

void Init_secure_db_fields(void) {
    mSecureDBFields = rb_define_module("SecureDBFields");
    mNative = rb_define_module_under(mSecureDBFields, "Native");

    eError = rb_define_class_under(mSecureDBFields, "Error", rb_eStandardError);
    eAuthError = rb_define_class_under(mSecureDBFields, "AuthenticationError", eError);
    eFormatError = rb_define_class_under(mSecureDBFields, "FormatError", eError);
    eKeyError = rb_define_class_under(mSecureDBFields, "KeyError", eError);

    rb_define_singleton_method(mNative, "version", rb_sdf_version, 0);
    rb_define_singleton_method(mNative, "encrypt", rb_sdf_encrypt, -1);
    rb_define_singleton_method(mNative, "decrypt", rb_sdf_decrypt, 3);
    rb_define_singleton_method(mNative, "key_id", rb_sdf_key_id, 1);
    rb_define_singleton_method(mNative, "valid_envelope?", rb_sdf_valid_envelope, 1);
    rb_define_singleton_method(mNative, "blind_index", rb_sdf_blind_index, 2);
    rb_define_singleton_method(mNative, "e164?", rb_sdf_e164_p, 1);
    rb_define_singleton_method(mNative, "phone_blind_index", rb_sdf_phone_bidx, 2);
    rb_define_singleton_method(mNative, "phone_prefix_blind_index", rb_sdf_phone_prefix_bidx, 3);
    rb_define_singleton_method(mNative, "encrypt_many", rb_sdf_encrypt_many, 4);
    rb_define_singleton_method(mNative, "decrypt_many", rb_sdf_decrypt_many, 3);
    rb_define_singleton_method(mNative, "blind_index_many", rb_sdf_blind_index_many, 2);
    rb_define_singleton_method(mNative, "blind_index_many_packed", rb_sdf_blind_index_many_packed,
                               2);
    rb_define_singleton_method(mNative, "phone_blind_index_many", rb_sdf_phone_bidx_many, 2);
    rb_define_singleton_method(mNative, "phone_blind_index_many_packed",
                               rb_sdf_phone_bidx_many_packed, 2);
    rb_define_singleton_method(mNative, "phone_prefix_blind_index_many",
                               rb_sdf_phone_prefix_bidx_many, 3);
    rb_define_singleton_method(mNative, "phone_prefix_blind_index_many_packed",
                               rb_sdf_phone_prefix_bidx_many_packed, 3);
    rb_define_singleton_method(mNative, "hex_decode_key", rb_sdf_hex_decode_key, 1);
}
