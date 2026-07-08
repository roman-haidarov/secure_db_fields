#include "secure_db_fields_core.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sdf_set_err(char *err, size_t err_len, const char *msg) {
    if (err && err_len > 0) {
        snprintf(err, err_len, "%s", msg ? msg : "unknown error");
    }
}

static void sdf_set_err2(char *err, size_t err_len, const char *prefix, const char *detail) {
    if (err && err_len > 0) {
        snprintf(err, err_len, "%s%s", prefix ? prefix : "", detail ? detail : "");
    }
}

const char *sdf_status_name(sdf_status status) {
    switch (status) {
    case SDF_OK:
        return "ok";
    case SDF_ERR_INVALID_ARGUMENT:
        return "invalid_argument";
    case SDF_ERR_NO_MEMORY:
        return "no_memory";
    case SDF_ERR_RANDOM:
        return "random_failed";
    case SDF_ERR_CRYPTO:
        return "crypto_failed";
    case SDF_ERR_AUTH:
        return "authentication_failed";
    case SDF_ERR_FORMAT:
        return "invalid_envelope";
    case SDF_ERR_KEY:
        return "key_error";
    case SDF_ERR_UNSUPPORTED:
        return "unsupported";
    default:
        return "unknown";
    }
}

void sdf_secure_clear(void *ptr, size_t len) {
    if (ptr && len > 0)
        OPENSSL_cleanse(ptr, len);
}

static void sdf_u32be_write(unsigned char *dst, uint32_t value) {
    dst[0] = (unsigned char)((value >> 24) & 0xff);
    dst[1] = (unsigned char)((value >> 16) & 0xff);
    dst[2] = (unsigned char)((value >> 8) & 0xff);
    dst[3] = (unsigned char)(value & 0xff);
}

static uint32_t sdf_u32be_read(const unsigned char *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) |
           ((uint32_t)src[3]);
}

static sdf_status sdf_validate_key(const unsigned char *key, size_t key_len, char *err,
                                   size_t err_len) {
    if (!key || key_len != SDF_KEY_BYTES) {
        sdf_set_err(err, err_len, "key must be exactly 32 bytes");
        return SDF_ERR_KEY;
    }
    return SDF_OK;
}

size_t sdf_encrypt_aes_256_gcm_output_len(size_t plaintext_len) {
    return SDF_HEADER_BYTES + plaintext_len;
}

sdf_status sdf_encrypt_aes_256_gcm_into(const unsigned char *plaintext, size_t plaintext_len,
                                        const unsigned char *key, size_t key_len,
                                        const unsigned char *aad, size_t aad_len, uint32_t key_id,
                                        unsigned char *out, size_t out_cap, size_t *out_len,
                                        char *err, size_t err_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[SDF_GCM_NONCE_BYTES];
    int len = 0;
    int total = 0;
    size_t needed;

    if (!out || !out_len || (!plaintext && plaintext_len > 0)) {
        sdf_set_err(err, err_len, "invalid encrypt arguments");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    *out_len = 0;
    if (sdf_validate_key(key, key_len, err, err_len) != SDF_OK)
        return SDF_ERR_KEY;
    if (!aad && aad_len > 0) {
        sdf_set_err(err, err_len, "aad pointer is NULL but aad_len > 0");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len > (size_t)INT_MAX || aad_len > (size_t)INT_MAX) {
        sdf_set_err(err, err_len, "input too large for OpenSSL EVP int lengths");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (key_id == 0) {
        sdf_set_err(err, err_len, "key_id must be positive");
        return SDF_ERR_INVALID_ARGUMENT;
    }

    needed = sdf_encrypt_aes_256_gcm_output_len(plaintext_len);
    if (out_cap < needed) {
        sdf_set_err(err, err_len, "output buffer too small");
        return SDF_ERR_INVALID_ARGUMENT;
    }

    if (RAND_bytes(nonce, SDF_GCM_NONCE_BYTES) != 1) {
        sdf_set_err(err, err_len, "RAND_bytes failed");
        return SDF_ERR_RANDOM;
    }

    memcpy(out, SDF_MAGIC, SDF_MAGIC_LEN);
    out[4] = SDF_ENVELOPE_VERSION;
    out[5] = SDF_ALG_AES_256_GCM;
    sdf_u32be_write(out + 6, key_id);
    memcpy(out + 10, nonce, SDF_GCM_NONCE_BYTES);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        sdf_set_err(err, err_len, "EVP_CIPHER_CTX_new failed");
        return SDF_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SDF_GCM_NONCE_BYTES, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP AES-256-GCM init failed");
        return SDF_ERR_CRYPTO;
    }

    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP AAD update failed");
        return SDF_ERR_CRYPTO;
    }

    if (EVP_EncryptUpdate(ctx, out + SDF_HEADER_BYTES, &len, plaintext_len > 0 ? plaintext : out,
                          (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP encrypt update failed");
        return SDF_ERR_CRYPTO;
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, out + SDF_HEADER_BYTES + total, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP encrypt final failed");
        return SDF_ERR_CRYPTO;
    }
    total += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SDF_GCM_TAG_BYTES,
                            out + 10 + SDF_GCM_NONCE_BYTES) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP get tag failed");
        return SDF_ERR_CRYPTO;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out_len = SDF_HEADER_BYTES + (size_t)total;
    return SDF_OK;
}

sdf_status sdf_encrypt_aes_256_gcm(const unsigned char *plaintext, size_t plaintext_len,
                                   const unsigned char *key, size_t key_len,
                                   const unsigned char *aad, size_t aad_len, uint32_t key_id,
                                   unsigned char **out, size_t *out_len, char *err,
                                   size_t err_len) {
    unsigned char *buf;
    size_t needed;
    sdf_status st;

    if (!out || !out_len) {
        sdf_set_err(err, err_len, "invalid encrypt arguments");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    *out_len = 0;
    needed = sdf_encrypt_aes_256_gcm_output_len(plaintext_len);
    buf = (unsigned char *)malloc(needed == 0 ? 1 : needed);
    if (!buf) {
        sdf_set_err(err, err_len, "malloc failed");
        return SDF_ERR_NO_MEMORY;
    }
    st = sdf_encrypt_aes_256_gcm_into(plaintext, plaintext_len, key, key_len, aad, aad_len, key_id,
                                      buf, needed, out_len, err, err_len);
    if (st != SDF_OK) {
        free(buf);
        return st;
    }
    *out = buf;
    return SDF_OK;
}

int sdf_is_valid_envelope(const unsigned char *envelope, size_t envelope_len) {
    if (!envelope || envelope_len < SDF_HEADER_BYTES)
        return 0;
    if (memcmp(envelope, SDF_MAGIC, SDF_MAGIC_LEN) != 0)
        return 0;
    if (envelope[4] != SDF_ENVELOPE_VERSION)
        return 0;
    if (envelope[5] != SDF_ALG_AES_256_GCM)
        return 0;
    if (sdf_u32be_read(envelope + 6) == 0)
        return 0;
    return 1;
}

sdf_status sdf_parse_key_id(const unsigned char *envelope, size_t envelope_len, uint32_t *key_id,
                            char *err, size_t err_len) {
    if (!key_id) {
        sdf_set_err(err, err_len, "key_id output is NULL");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (!sdf_is_valid_envelope(envelope, envelope_len)) {
        sdf_set_err(err, err_len, "invalid MCEN envelope");
        return SDF_ERR_FORMAT;
    }
    *key_id = sdf_u32be_read(envelope + 6);
    return SDF_OK;
}

size_t sdf_decrypt_aes_256_gcm_output_cap(const unsigned char *envelope, size_t envelope_len) {
    if (!sdf_is_valid_envelope(envelope, envelope_len))
        return 0;
    return envelope_len - SDF_HEADER_BYTES;
}

sdf_status sdf_decrypt_aes_256_gcm_into(const unsigned char *envelope, size_t envelope_len,
                                        const unsigned char *key, size_t key_len,
                                        const unsigned char *aad, size_t aad_len,
                                        unsigned char *out, size_t out_cap, size_t *out_len,
                                        char *err, size_t err_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    const unsigned char *nonce;
    const unsigned char *tag;
    const unsigned char *ciphertext;
    size_t ciphertext_len;
    int len = 0;
    int total = 0;
    int final_ok = 0;
    unsigned char dummy_out[1];
    unsigned char *out_ptr = out ? out : dummy_out;

    if (!out_len || !envelope || (!out && out_cap > 0)) {
        sdf_set_err(err, err_len, "invalid decrypt arguments");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    *out_len = 0;
    if (sdf_validate_key(key, key_len, err, err_len) != SDF_OK)
        return SDF_ERR_KEY;
    if (!aad && aad_len > 0) {
        sdf_set_err(err, err_len, "aad pointer is NULL but aad_len > 0");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (!sdf_is_valid_envelope(envelope, envelope_len)) {
        sdf_set_err(err, err_len, "invalid MCEN envelope");
        return SDF_ERR_FORMAT;
    }
    if (aad_len > (size_t)INT_MAX) {
        sdf_set_err(err, err_len, "aad too large for OpenSSL EVP int lengths");
        return SDF_ERR_INVALID_ARGUMENT;
    }

    nonce = envelope + 10;
    tag = envelope + 10 + SDF_GCM_NONCE_BYTES;
    ciphertext = envelope + SDF_HEADER_BYTES;
    ciphertext_len = envelope_len - SDF_HEADER_BYTES;
    if (ciphertext_len > (size_t)INT_MAX) {
        sdf_set_err(err, err_len, "ciphertext too large for OpenSSL EVP int lengths");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (out_cap < ciphertext_len) {
        sdf_set_err(err, err_len, "output buffer too small");
        return SDF_ERR_INVALID_ARGUMENT;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        sdf_set_err(err, err_len, "EVP_CIPHER_CTX_new failed");
        return SDF_ERR_CRYPTO;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SDF_GCM_NONCE_BYTES, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP AES-256-GCM init failed");
        return SDF_ERR_CRYPTO;
    }

    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP AAD update failed");
        return SDF_ERR_CRYPTO;
    }

    if (EVP_DecryptUpdate(ctx, out_ptr, &len, ciphertext_len > 0 ? ciphertext : out_ptr,
                          (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP decrypt update failed");
        return SDF_ERR_CRYPTO;
    }
    total = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SDF_GCM_TAG_BYTES, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        sdf_set_err(err, err_len, "EVP set tag failed");
        return SDF_ERR_CRYPTO;
    }

    final_ok = EVP_DecryptFinal_ex(ctx, out_ptr + total, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (final_ok != 1) {
        if (out && out_cap > 0)
            sdf_secure_clear(out, out_cap);
        sdf_secure_clear(dummy_out, sizeof(dummy_out));
        sdf_set_err(err, err_len, "authentication failed");
        return SDF_ERR_AUTH;
    }
    total += len;

    *out_len = (size_t)total;
    return SDF_OK;
}

sdf_status sdf_decrypt_aes_256_gcm(const unsigned char *envelope, size_t envelope_len,
                                   const unsigned char *key, size_t key_len,
                                   const unsigned char *aad, size_t aad_len, unsigned char **out,
                                   size_t *out_len, char *err, size_t err_len) {
    unsigned char *buf;
    size_t cap;
    sdf_status st;

    if (!out || !out_len || !envelope) {
        sdf_set_err(err, err_len, "invalid decrypt arguments");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    *out_len = 0;
    cap = sdf_decrypt_aes_256_gcm_output_cap(envelope, envelope_len);
    if (cap == 0 && !sdf_is_valid_envelope(envelope, envelope_len)) {
        sdf_set_err(err, err_len, "invalid MCEN envelope");
        return SDF_ERR_FORMAT;
    }
    buf = (unsigned char *)malloc(cap == 0 ? 1 : cap);
    if (!buf) {
        sdf_set_err(err, err_len, "malloc failed");
        return SDF_ERR_NO_MEMORY;
    }
    st = sdf_decrypt_aes_256_gcm_into(envelope, envelope_len, key, key_len, aad, aad_len, buf, cap,
                                      out_len, err, err_len);
    if (st != SDF_OK) {
        sdf_secure_clear(buf, cap == 0 ? 1 : cap);
        free(buf);
        return st;
    }
    *out = buf;
    return SDF_OK;
}

sdf_status sdf_blind_index(const unsigned char *value, size_t value_len, const unsigned char *key,
                           size_t key_len, unsigned char out[SDF_BIDX_BYTES], char *err,
                           size_t err_len) {
    unsigned int out_len = 0;
    if ((!value && value_len > 0) || !out) {
        sdf_set_err(err, err_len, "invalid blind index arguments");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (sdf_validate_key(key, key_len, err, err_len) != SDF_OK)
        return SDF_ERR_KEY;
    if (!HMAC(EVP_sha256(), key, (int)key_len, value, value_len, out, &out_len) ||
        out_len != SDF_BIDX_BYTES) {
        sdf_set_err(err, err_len, "HMAC-SHA256 failed");
        return SDF_ERR_CRYPTO;
    }
    return SDF_OK;
}

int sdf_is_canonical_e164(const unsigned char *value, size_t value_len) {
    size_t i;
    if (!value || value_len < 3 || value_len > 16)
        return 0;
    if (value[0] != '+')
        return 0;
    if (value[1] == '0')
        return 0;
    for (i = 1; i < value_len; i++) {
        if (value[i] < '0' || value[i] > '9')
            return 0;
    }
    return 1;
}

sdf_status sdf_phone_exact_bidx(const unsigned char *e164, size_t e164_len,
                                const unsigned char *key, size_t key_len,
                                unsigned char out[SDF_BIDX_BYTES], char *err, size_t err_len) {
    if (!sdf_is_canonical_e164(e164, e164_len)) {
        sdf_set_err(err, err_len, "phone must be canonical E.164, e.g. +77771234567");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    return sdf_blind_index(e164, e164_len, key, key_len, out, err, err_len);
}

sdf_status sdf_phone_prefix_bidx(const unsigned char *e164, size_t e164_len,
                                 unsigned int prefix_digits, const unsigned char *key,
                                 size_t key_len, unsigned char out[SDF_BIDX_BYTES], char *err,
                                 size_t err_len) {
    size_t prefix_len;
    if (!sdf_is_canonical_e164(e164, e164_len)) {
        sdf_set_err(err, err_len, "phone must be canonical E.164, e.g. +77771234567");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (prefix_digits == 0 || prefix_digits > 15) {
        sdf_set_err(err, err_len, "prefix_digits must be between 1 and 15");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if ((size_t)prefix_digits > e164_len - 1) {
        sdf_set_err(err, err_len, "prefix_digits exceeds phone digit length");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    prefix_len = 1 + (size_t)prefix_digits; /* include '+' to bind canonical form */
    return sdf_blind_index(e164, prefix_len, key, key_len, out, err, err_len);
}

static int sdf_hex_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

sdf_status sdf_hex_decode_32(const char *hex, unsigned char out[SDF_KEY_BYTES], char *err,
                             size_t err_len) {
    size_t i;
    if (!hex || !out) {
        sdf_set_err(err, err_len, "hex key is NULL");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    if (strlen(hex) != SDF_KEY_BYTES * 2) {
        sdf_set_err(err, err_len, "hex key must be exactly 64 hex characters");
        return SDF_ERR_KEY;
    }
    for (i = 0; i < SDF_KEY_BYTES; i++) {
        int hi = sdf_hex_value(hex[i * 2]);
        int lo = sdf_hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            sdf_set_err(err, err_len, "hex key contains non-hex characters");
            return SDF_ERR_KEY;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return SDF_OK;
}

static char *sdf_trim(char *s) {
    char *end;
    while (*s && isspace((unsigned char)*s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1)))
        end--;
    *end = '\0';
    return s;
}

sdf_status sdf_load_key_from_env_file(const char *path, const char *name,
                                      unsigned char out[SDF_KEY_BYTES], char *err, size_t err_len) {
    FILE *fp;
    char line[SDF_MAX_KEY_LINE];
    size_t name_len;
    const char *effective_path = path && path[0] ? path : SDF_DEFAULT_KEY_FILE;
    if (!name || !out) {
        sdf_set_err(err, err_len, "invalid key lookup arguments");
        return SDF_ERR_INVALID_ARGUMENT;
    }
    fp = fopen(effective_path, "r");
    if (!fp) {
        sdf_set_err2(err, err_len, "cannot open key file: ", effective_path);
        return SDF_ERR_KEY;
    }
    name_len = strlen(name);
    while (fgets(line, sizeof(line), fp)) {
        char *p = sdf_trim(line);
        char *eq;
        if (*p == '\0' || *p == '#')
            continue;
        eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        if (strcmp(sdf_trim(p), name) == 0) {
            char *value = sdf_trim(eq + 1);
            sdf_status st;
            (void)name_len;
            fclose(fp);
            st = sdf_hex_decode_32(value, out, err, err_len);
            return st;
        }
    }
    fclose(fp);
    sdf_set_err2(err, err_len, "key not found in key file: ", name);
    return SDF_ERR_KEY;
}

sdf_status sdf_load_encryption_key(uint32_t key_id, const char *path,
                                   unsigned char out[SDF_KEY_BYTES], char *err, size_t err_len) {
    char name[64];
    sdf_status st;
    snprintf(name, sizeof(name), "SDF_ENC_KEY_%u_HEX", key_id);
    st = sdf_load_key_from_env_file(path, name, out, err, err_len);
    if (st == SDF_OK)
        return st;
    if (key_id == 1) {
        return sdf_load_key_from_env_file(path, "SDF_ENC_KEY_HEX", out, err, err_len);
    }
    return st;
}

sdf_status sdf_load_bidx_key(const char *path, const char *domain, unsigned char out[SDF_KEY_BYTES],
                             char *err, size_t err_len) {
    char name[128];
    size_t i;
    if (!domain || !domain[0]) {
        return sdf_load_key_from_env_file(path, "SDF_BIDX_KEY_HEX", out, err, err_len);
    }
    if (strlen(domain) > 80) {
        sdf_set_err(err, err_len, "bidx domain is too long");
        return SDF_ERR_KEY;
    }
    snprintf(name, sizeof(name), "SDF_BIDX_%s_KEY_HEX", domain);
    for (i = 0; name[i]; i++) {
        if (name[i] >= 'a' && name[i] <= 'z')
            name[i] = (char)(name[i] - 32);
        if (!(name[i] == '_' || (name[i] >= 'A' && name[i] <= 'Z') ||
              (name[i] >= '0' && name[i] <= '9'))) {
            name[i] = '_';
        }
    }
    return sdf_load_key_from_env_file(path, name, out, err, err_len);
}
