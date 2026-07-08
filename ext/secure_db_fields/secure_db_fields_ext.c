#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <ruby.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "secure_db_fields_core.h"

static VALUE mSecureDBFields;
static VALUE mNative;
static VALUE eError;
static VALUE eAuthError;
static VALUE eFormatError;
static VALUE eKeyError;

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

static void rb_sdf_hmac_key_init(sdf_hmac_sha256_key *prepared, VALUE key) {
    char err[SDF_MAX_ERR];
    sdf_status st;

    rb_sdf_assert_key_value(&key);
    st = sdf_hmac_sha256_key_prepare(prepared, (const unsigned char *)RSTRING_PTR(key),
                                     (size_t)RSTRING_LEN(key), err, sizeof(err));
    if (st != SDF_OK)
        rb_sdf_raise(st, err);
}

static VALUE rb_sdf_bidx_string(const unsigned char out[SDF_BIDX_BYTES]) {
    return rb_str_new((const char *)out, SDF_BIDX_BYTES);
}

static VALUE rb_sdf_version(VALUE self) {
    (void)self;
    return rb_str_new_cstr(SDF_VERSION);
}

static VALUE rb_sdf_encrypt_one(VALUE plaintext, VALUE key, VALUE aad, uint32_t key_id) {
    char err[SDF_MAX_ERR];
    sdf_status st;
    size_t out_len = 0;
    size_t out_cap;
    VALUE result;

    StringValue(plaintext);
    StringValue(aad);
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

static VALUE rb_sdf_decrypt_one(VALUE envelope, VALUE key, VALUE aad) {
    char err[SDF_MAX_ERR];
    sdf_status st;
    size_t out_cap;
    size_t out_len = 0;
    VALUE result;

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

static VALUE rb_sdf_encrypt(int argc, VALUE *argv, VALUE self) {
    VALUE plaintext, key, aad, key_id_value;
    uint32_t key_id = 1;
    (void)self;

    rb_scan_args(argc, argv, "31", &plaintext, &key, &aad, &key_id_value);
    rb_sdf_assert_key_value(&key);
    if (!NIL_P(key_id_value))
        key_id = rb_sdf_key_id_from_value(key_id_value);
    return rb_sdf_encrypt_one(plaintext, key, aad, key_id);
}

static VALUE rb_sdf_decrypt(VALUE self, VALUE envelope, VALUE key, VALUE aad) {
    (void)self;
    rb_sdf_assert_key_value(&key);
    return rb_sdf_decrypt_one(envelope, key, aad);
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

typedef enum {
    SDF_RB_BIDX_RAW = 0,
    SDF_RB_BIDX_PHONE = 1,
    SDF_RB_BIDX_PHONE_PREFIX = 2
} sdf_rb_bidx_kind;

static void rb_sdf_bidx_raise(sdf_status st, const char *err, sdf_hmac_sha256_key *prepared,
                              unsigned char *packed, size_t packed_len,
                              unsigned char out[SDF_BIDX_BYTES]) {
    if (packed && packed_len > 0)
        sdf_secure_clear(packed, packed_len);
    if (out)
        sdf_secure_clear(out, SDF_BIDX_BYTES);
    sdf_hmac_sha256_key_clear(prepared);
    if (st == SDF_ERR_INVALID_ARGUMENT)
        rb_raise(rb_eArgError, "%s", err && err[0] ? err : "invalid argument");
    rb_sdf_raise(st, err);
}

static VALUE rb_sdf_bidx_many_impl(VALUE values, VALUE key, int packed, sdf_rb_bidx_kind kind,
                                   unsigned long prefix_digits) {
    long i, n;
    VALUE result;
    sdf_hmac_sha256_key prepared;
    unsigned char out[SDF_BIDX_BYTES];
    unsigned char *dst = NULL;
    size_t packed_len = 0;

    Check_Type(values, T_ARRAY);
    if (kind == SDF_RB_BIDX_PHONE_PREFIX && (prefix_digits == 0 || prefix_digits > 15))
        rb_raise(rb_eArgError, "prefix_digits must be between 1 and 15");

    rb_sdf_hmac_key_init(&prepared, key);
    n = RARRAY_LEN(values);
    if (packed) {
        rb_sdf_assert_packed_len(n);
        packed_len = (size_t)n * SDF_BIDX_BYTES;
        result = rb_str_new(NULL, (long)packed_len);
        dst = (unsigned char *)RSTRING_PTR(result);
    } else {
        result = rb_ary_new_capa(n);
    }

    for (i = 0; i < n; i++) {
        VALUE value = rb_ary_entry(values, i);
        unsigned char *target = packed ? dst + ((size_t)i * SDF_BIDX_BYTES) : out;
        char err[SDF_MAX_ERR];
        sdf_status st;
        StringValue(value);
        if (kind == SDF_RB_BIDX_PHONE) {
            st = sdf_phone_exact_bidx_prepared((const unsigned char *)RSTRING_PTR(value),
                                               (size_t)RSTRING_LEN(value), &prepared, target, err,
                                               sizeof(err));
        } else if (kind == SDF_RB_BIDX_PHONE_PREFIX) {
            st = sdf_phone_prefix_bidx_prepared(
                (const unsigned char *)RSTRING_PTR(value), (size_t)RSTRING_LEN(value),
                (unsigned int)prefix_digits, &prepared, target, err, sizeof(err));
        } else {
            st = sdf_blind_index_prepared((const unsigned char *)RSTRING_PTR(value),
                                          (size_t)RSTRING_LEN(value), &prepared, target, err,
                                          sizeof(err));
        }
        if (st != SDF_OK)
            rb_sdf_bidx_raise(st, err, &prepared, dst, packed_len, packed ? NULL : out);
        if (!packed)
            rb_ary_push(result, rb_sdf_bidx_string(out));
    }

    if (!packed)
        sdf_secure_clear(out, sizeof(out));
    sdf_hmac_sha256_key_clear(&prepared);
    return result;
}

static VALUE rb_sdf_blind_index_many(VALUE self, VALUE values, VALUE key) {
    (void)self;
    return rb_sdf_bidx_many_impl(values, key, 0, SDF_RB_BIDX_RAW, 0);
}

static VALUE rb_sdf_blind_index_many_packed(VALUE self, VALUE values, VALUE key) {
    (void)self;
    return rb_sdf_bidx_many_impl(values, key, 1, SDF_RB_BIDX_RAW, 0);
}

static VALUE rb_sdf_phone_bidx_many(VALUE self, VALUE values, VALUE key) {
    (void)self;
    return rb_sdf_bidx_many_impl(values, key, 0, SDF_RB_BIDX_PHONE, 0);
}

static VALUE rb_sdf_phone_bidx_many_packed(VALUE self, VALUE values, VALUE key) {
    (void)self;
    return rb_sdf_bidx_many_impl(values, key, 1, SDF_RB_BIDX_PHONE, 0);
}

static VALUE rb_sdf_phone_prefix_bidx_many(VALUE self, VALUE values, VALUE prefix_digits_value,
                                           VALUE key) {
    (void)self;
    return rb_sdf_bidx_many_impl(values, key, 0, SDF_RB_BIDX_PHONE_PREFIX,
                                 NUM2ULONG(prefix_digits_value));
}

static VALUE rb_sdf_phone_prefix_bidx_many_packed(VALUE self, VALUE values,
                                                  VALUE prefix_digits_value, VALUE key) {
    (void)self;
    return rb_sdf_bidx_many_impl(values, key, 1, SDF_RB_BIDX_PHONE_PREFIX,
                                 NUM2ULONG(prefix_digits_value));
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
    for (i = 0; i < n; i++)
        rb_ary_push(result, rb_sdf_encrypt_one(rb_ary_entry(values, i), key, rb_ary_entry(aads, i),
                                               key_id));
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
    for (i = 0; i < n; i++)
        rb_ary_push(result,
                    rb_sdf_decrypt_one(rb_ary_entry(envelopes, i), key, rb_ary_entry(aads, i)));
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

typedef struct {
    const char *name;
    VALUE (*func)(ANYARGS);
    int arity;
} rb_sdf_method;

static const rb_sdf_method rb_sdf_methods[] = {
    {"version", rb_sdf_version, 0},
    {"encrypt", rb_sdf_encrypt, -1},
    {"decrypt", rb_sdf_decrypt, 3},
    {"key_id", rb_sdf_key_id, 1},
    {"valid_envelope?", rb_sdf_valid_envelope, 1},
    {"blind_index", rb_sdf_blind_index, 2},
    {"e164?", rb_sdf_e164_p, 1},
    {"phone_blind_index", rb_sdf_phone_bidx, 2},
    {"phone_prefix_blind_index", rb_sdf_phone_prefix_bidx, 3},
    {"encrypt_many", rb_sdf_encrypt_many, 4},
    {"decrypt_many", rb_sdf_decrypt_many, 3},
    {"blind_index_many", rb_sdf_blind_index_many, 2},
    {"blind_index_many_packed", rb_sdf_blind_index_many_packed, 2},
    {"phone_blind_index_many", rb_sdf_phone_bidx_many, 2},
    {"phone_blind_index_many_packed", rb_sdf_phone_bidx_many_packed, 2},
    {"phone_prefix_blind_index_many", rb_sdf_phone_prefix_bidx_many, 3},
    {"phone_prefix_blind_index_many_packed", rb_sdf_phone_prefix_bidx_many_packed, 3},
    {"hex_decode_key", rb_sdf_hex_decode_key, 1}};

void Init_secure_db_fields(void) {
    size_t i;
    mSecureDBFields = rb_define_module("SecureDBFields");
    mNative = rb_define_module_under(mSecureDBFields, "Native");

    eError = rb_define_class_under(mSecureDBFields, "Error", rb_eStandardError);
    eAuthError = rb_define_class_under(mSecureDBFields, "AuthenticationError", eError);
    eFormatError = rb_define_class_under(mSecureDBFields, "FormatError", eError);
    eKeyError = rb_define_class_under(mSecureDBFields, "KeyError", eError);

    for (i = 0; i < sizeof(rb_sdf_methods) / sizeof(rb_sdf_methods[0]); i++)
        rb_define_singleton_method(mNative, rb_sdf_methods[i].name, rb_sdf_methods[i].func,
                                   rb_sdf_methods[i].arity);
}
