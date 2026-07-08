#ifndef SECURE_DB_FIELDS_CORE_H
#define SECURE_DB_FIELDS_CORE_H

#include <stddef.h>
#include <stdint.h>

#define SDF_VERSION "0.1.1"

#define SDF_MAGIC "MCEN"
#define SDF_MAGIC_LEN 4
#define SDF_ENVELOPE_VERSION 1
#define SDF_ALG_AES_256_GCM 1
#define SDF_KEY_BYTES 32
#define SDF_GCM_NONCE_BYTES 12
#define SDF_GCM_TAG_BYTES 16
#define SDF_BIDX_BYTES 32
#define SDF_ROW_UID_BYTES 16
#define SDF_HEADER_BYTES (SDF_MAGIC_LEN + 1 + 1 + 4 + SDF_GCM_NONCE_BYTES + SDF_GCM_TAG_BYTES)
#define SDF_MAX_ERR 256
#define SDF_MAX_KEY_LINE 512
#define SDF_DEFAULT_KEY_FILE "/etc/secure_db_fields/keys.env"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SDF_OK = 0,
    SDF_ERR_INVALID_ARGUMENT = 1,
    SDF_ERR_NO_MEMORY = 2,
    SDF_ERR_RANDOM = 3,
    SDF_ERR_CRYPTO = 4,
    SDF_ERR_AUTH = 5,
    SDF_ERR_FORMAT = 6,
    SDF_ERR_KEY = 7,
    SDF_ERR_UNSUPPORTED = 8
} sdf_status;

const char *sdf_status_name(sdf_status status);

sdf_status sdf_encrypt_aes_256_gcm(const unsigned char *plaintext, size_t plaintext_len,
                                   const unsigned char *key, size_t key_len,
                                   const unsigned char *aad, size_t aad_len,
                                   uint32_t key_id,
                                   unsigned char **out, size_t *out_len,
                                   char *err, size_t err_len);

sdf_status sdf_decrypt_aes_256_gcm(const unsigned char *envelope, size_t envelope_len,
                                   const unsigned char *key, size_t key_len,
                                   const unsigned char *aad, size_t aad_len,
                                   unsigned char **out, size_t *out_len,
                                   char *err, size_t err_len);

sdf_status sdf_parse_key_id(const unsigned char *envelope, size_t envelope_len,
                            uint32_t *key_id, char *err, size_t err_len);

int sdf_is_valid_envelope(const unsigned char *envelope, size_t envelope_len);

sdf_status sdf_blind_index(const unsigned char *value, size_t value_len,
                           const unsigned char *key, size_t key_len,
                           unsigned char out[SDF_BIDX_BYTES],
                           char *err, size_t err_len);

int sdf_is_canonical_e164(const unsigned char *value, size_t value_len);

sdf_status sdf_phone_exact_bidx(const unsigned char *e164, size_t e164_len,
                                const unsigned char *key, size_t key_len,
                                unsigned char out[SDF_BIDX_BYTES],
                                char *err, size_t err_len);

sdf_status sdf_phone_prefix_bidx(const unsigned char *e164, size_t e164_len,
                                 unsigned int prefix_digits,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char out[SDF_BIDX_BYTES],
                                 char *err, size_t err_len);

sdf_status sdf_hex_decode_32(const char *hex, unsigned char out[SDF_KEY_BYTES],
                             char *err, size_t err_len);

sdf_status sdf_load_key_from_env_file(const char *path, const char *name,
                                      unsigned char out[SDF_KEY_BYTES],
                                      char *err, size_t err_len);

sdf_status sdf_load_encryption_key(uint32_t key_id, const char *path,
                                   unsigned char out[SDF_KEY_BYTES],
                                   char *err, size_t err_len);

sdf_status sdf_load_bidx_key(const char *path, const char *domain,
                             unsigned char out[SDF_KEY_BYTES],
                             char *err, size_t err_len);

void sdf_secure_clear(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
