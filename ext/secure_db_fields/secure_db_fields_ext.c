#include <ruby.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "secure_db_fields_core.h"

static VALUE mSecureDBFields;
static VALUE mNative;
static VALUE eError;
static VALUE eAuthError;
static VALUE eFormatError;
static VALUE eKeyError;

static void rb_sdf_raise(sdf_status st, const char *err) {
    VALUE klass = eError;
    if (st == SDF_ERR_AUTH) klass = eAuthError;
    else if (st == SDF_ERR_FORMAT) klass = eFormatError;
    else if (st == SDF_ERR_KEY) klass = eKeyError;
    rb_raise(klass, "%s: %s", sdf_status_name(st), err && err[0] ? err : "unknown error");
}

static VALUE rb_sdf_version(VALUE self) {
    (void)self;
    return rb_str_new_cstr(SDF_VERSION);
}

static VALUE rb_sdf_encrypt(int argc, VALUE *argv, VALUE self) {
    VALUE plaintext, key, aad, key_id_value;
    unsigned char *out = NULL;
    size_t out_len = 0;
    char err[SDF_MAX_ERR];
    sdf_status st;
    uint32_t key_id = 1;
    (void)self;

    rb_scan_args(argc, argv, "31", &plaintext, &key, &aad, &key_id_value);
    StringValue(plaintext);
    StringValue(key);
    StringValue(aad);
    if (!NIL_P(key_id_value)) {
        unsigned long id = NUM2ULONG(key_id_value);
        if (id == 0 || id > UINT32_MAX) rb_raise(rb_eArgError, "key_id must be between 1 and 2^32-1");
        key_id = (uint32_t)id;
    }

    st = sdf_encrypt_aes_256_gcm((const unsigned char *)RSTRING_PTR(plaintext), (size_t)RSTRING_LEN(plaintext),
                                 (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
                                 (const unsigned char *)RSTRING_PTR(aad), (size_t)RSTRING_LEN(aad),
                                 key_id, &out, &out_len, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
    VALUE result = rb_str_new((const char *)out, (long)out_len);
    free(out);
    return result;
}

static VALUE rb_sdf_decrypt(VALUE self, VALUE envelope, VALUE key, VALUE aad) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;

    StringValue(envelope);
    StringValue(key);
    StringValue(aad);
    st = sdf_decrypt_aes_256_gcm((const unsigned char *)RSTRING_PTR(envelope), (size_t)RSTRING_LEN(envelope),
                                 (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
                                 (const unsigned char *)RSTRING_PTR(aad), (size_t)RSTRING_LEN(aad),
                                 &out, &out_len, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
    VALUE result = rb_str_new((const char *)out, (long)out_len);
    sdf_secure_clear(out, out_len);
    free(out);
    return result;
}

static VALUE rb_sdf_key_id(VALUE self, VALUE envelope) {
    uint32_t key_id = 0;
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(envelope);
    st = sdf_parse_key_id((const unsigned char *)RSTRING_PTR(envelope), (size_t)RSTRING_LEN(envelope),
                          &key_id, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
    return UINT2NUM(key_id);
}

static VALUE rb_sdf_valid_envelope(VALUE self, VALUE envelope) {
    (void)self;
    StringValue(envelope);
    return sdf_is_valid_envelope((const unsigned char *)RSTRING_PTR(envelope), (size_t)RSTRING_LEN(envelope)) ? Qtrue : Qfalse;
}

static VALUE rb_sdf_blind_index(VALUE self, VALUE value, VALUE key) {
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(value);
    StringValue(key);
    st = sdf_blind_index((const unsigned char *)RSTRING_PTR(value), (size_t)RSTRING_LEN(value),
                         (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
                         out, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
    return rb_str_new((const char *)out, SDF_BIDX_BYTES);
}

static VALUE rb_sdf_e164_p(VALUE self, VALUE value) {
    (void)self;
    StringValue(value);
    return sdf_is_canonical_e164((const unsigned char *)RSTRING_PTR(value), (size_t)RSTRING_LEN(value)) ? Qtrue : Qfalse;
}

static VALUE rb_sdf_phone_bidx(VALUE self, VALUE e164, VALUE key) {
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(e164);
    StringValue(key);
    st = sdf_phone_exact_bidx((const unsigned char *)RSTRING_PTR(e164), (size_t)RSTRING_LEN(e164),
                              (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
                              out, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
    return rb_str_new((const char *)out, SDF_BIDX_BYTES);
}

static VALUE rb_sdf_phone_prefix_bidx(VALUE self, VALUE e164, VALUE prefix_digits_value, VALUE key) {
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    unsigned long prefix_digits;
    (void)self;
    StringValue(e164);
    StringValue(key);
    prefix_digits = NUM2ULONG(prefix_digits_value);
    if (prefix_digits > 15) rb_raise(rb_eArgError, "prefix_digits must be between 1 and 15");
    st = sdf_phone_prefix_bidx((const unsigned char *)RSTRING_PTR(e164), (size_t)RSTRING_LEN(e164),
                               (unsigned int)prefix_digits,
                               (const unsigned char *)RSTRING_PTR(key), (size_t)RSTRING_LEN(key),
                               out, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
    return rb_str_new((const char *)out, SDF_BIDX_BYTES);
}

static VALUE rb_sdf_hex_decode_key(VALUE self, VALUE hex) {
    unsigned char out[SDF_KEY_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)self;
    StringValue(hex);
    st = sdf_hex_decode_32(StringValueCStr(hex), out, err, sizeof(err));
    if (st != SDF_OK) rb_sdf_raise(st, err);
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
    rb_define_singleton_method(mNative, "hex_decode_key", rb_sdf_hex_decode_key, 1);
}
