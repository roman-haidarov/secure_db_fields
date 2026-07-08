#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef SDF_MYSQL_UDF_ABI_57
#include "mysql_udf_abi_57.h"
typedef my_bool sdf_udf_init_result_t;
#else
#include <stdbool.h>
#include <mysql.h>
#if defined(MARIADB_BASE_VERSION) || defined(MARIADB_VERSION_ID) || \
    (defined(MYSQL_VERSION_ID) && MYSQL_VERSION_ID < 80000)
typedef my_bool sdf_udf_init_result_t;
#else
typedef bool sdf_udf_init_result_t;
#endif
#endif

#include "secure_db_fields_core.h"

#ifndef SDF_UDF_KEY_FILE
#define SDF_UDF_KEY_FILE SDF_DEFAULT_KEY_FILE
#endif

typedef struct {
    char *out;
    unsigned long out_cap;
    char *scratch;
    unsigned long scratch_cap;
    int enc_key_valid;
    uint32_t enc_key_id;
    unsigned char enc_key[SDF_KEY_BYTES];
    int bidx_key_valid;
    char bidx_domain[128];
    unsigned char bidx_key[SDF_KEY_BYTES];
} sdf_mysql_state;

static const char *sdf_mysql_key_file(void) {
    const char *env = getenv("SECURE_DB_FIELDS_KEY_FILE");
    return (env && env[0]) ? env : SDF_UDF_KEY_FILE;
}

static void sdf_mysql_u32be_write(char *dst, uint32_t value) {
    dst[0] = (char)((value >> 24) & 0xff);
    dst[1] = (char)((value >> 16) & 0xff);
    dst[2] = (char)((value >> 8) & 0xff);
    dst[3] = (char)(value & 0xff);
}

static sdf_mysql_state *sdf_mysql_state_new(void) {
    return (sdf_mysql_state *)calloc(1, sizeof(sdf_mysql_state));
}

static void sdf_mysql_state_free(sdf_mysql_state *state) {
    if (!state)
        return;
    if (state->out) {
        sdf_secure_clear(state->out, state->out_cap);
        free(state->out);
    }
    if (state->scratch) {
        sdf_secure_clear(state->scratch, state->scratch_cap);
        free(state->scratch);
    }
    if (state->enc_key_valid)
        sdf_secure_clear(state->enc_key, sizeof(state->enc_key));
    if (state->bidx_key_valid)
        sdf_secure_clear(state->bidx_key, sizeof(state->bidx_key));
    free(state);
}

static int sdf_mysql_ensure_out(sdf_mysql_state *state, unsigned long need) {
    char *next;
    if (need == 0)
        need = 1;
    if (state->out_cap >= need)
        return 1;
    next = (char *)realloc(state->out, need);
    if (!next)
        return 0;
    state->out = next;
    state->out_cap = need;
    return 1;
}

static int sdf_mysql_ensure_scratch(sdf_mysql_state *state, unsigned long need) {
    char *next;
    if (need == 0)
        need = 1;
    if (state->scratch_cap >= need)
        return 1;
    next = (char *)realloc(state->scratch, need);
    if (!next)
        return 0;
    state->scratch = next;
    state->scratch_cap = need;
    return 1;
}

static sdf_status sdf_mysql_cached_encryption_key(sdf_mysql_state *state, uint32_t key_id,
                                                  char *err, size_t err_len) {
    sdf_status st;
    if (state->enc_key_valid && state->enc_key_id == key_id)
        return SDF_OK;
    if (state->enc_key_valid) {
        sdf_secure_clear(state->enc_key, sizeof(state->enc_key));
        state->enc_key_valid = 0;
    }
    st = sdf_load_encryption_key(key_id, sdf_mysql_key_file(), state->enc_key, err, err_len);
    if (st == SDF_OK) {
        state->enc_key_id = key_id;
        state->enc_key_valid = 1;
    }
    return st;
}

static sdf_status sdf_mysql_cached_bidx_key(sdf_mysql_state *state, const char *domain, char *err,
                                            size_t err_len) {
    sdf_status st;
    const char *effective_domain = domain ? domain : "";
    if (strlen(effective_domain) >= sizeof(state->bidx_domain)) {
        snprintf(err, err_len, "bidx domain is too long");
        return SDF_ERR_KEY;
    }
    if (state->bidx_key_valid && strcmp(state->bidx_domain, effective_domain) == 0)
        return SDF_OK;
    if (state->bidx_key_valid) {
        sdf_secure_clear(state->bidx_key, sizeof(state->bidx_key));
        state->bidx_key_valid = 0;
    }
    st = sdf_load_bidx_key(sdf_mysql_key_file(), effective_domain, state->bidx_key, err, err_len);
    if (st == SDF_OK) {
        snprintf(state->bidx_domain, sizeof(state->bidx_domain), "%s", effective_domain);
        state->bidx_key_valid = 1;
    }
    return st;
}

static sdf_udf_init_result_t sdf_init_state(UDF_INIT *initid, UDF_ARGS *args, char *message,
                                            unsigned int argc, const char *signature,
                                            unsigned long max_length) {
    unsigned int i;
    sdf_mysql_state *state;
    if (args->arg_count != argc) {
        snprintf(message, 255, "%s takes exactly %u arguments", signature, argc);
        return 1;
    }
    for (i = 0; i < argc; i++)
        args->arg_type[i] = STRING_RESULT;
    state = sdf_mysql_state_new();
    if (!state) {
        snprintf(message, 255, "out of memory");
        return 1;
    }
    initid->ptr = (char *)state;
    initid->maybe_null = 1;
    initid->const_item = 0;
    initid->max_length = max_length;
    return 0;
}

static sdf_udf_init_result_t sdf_init_no_state(UDF_INIT *initid, UDF_ARGS *args, char *message,
                                               unsigned int argc, const char *signature,
                                               unsigned long max_length) {
    if (args->arg_count != argc) {
        snprintf(message, 255, "%s takes exactly %u arguments", signature, argc);
        return 1;
    }
    initid->maybe_null = 1;
    initid->const_item = 0;
    initid->max_length = max_length;
    return 0;
}

void secure_db_fields_deinit(UDF_INIT *initid) {
    sdf_mysql_state_free((sdf_mysql_state *)initid->ptr);
    initid->ptr = NULL;
}

sdf_udf_init_result_t secure_db_fields_version_init(UDF_INIT *initid, UDF_ARGS *args,
                                                    char *message) {
    (void)initid;
    if (args->arg_count != 0) {
        snprintf(message, 255, "secure_db_fields_version() takes no arguments");
        return 1;
    }
    initid->maybe_null = 0;
    initid->const_item = 1;
    initid->max_length = 128;
    return 0;
}

char *secure_db_fields_version(UDF_INIT *initid, UDF_ARGS *args, char *result,
                               unsigned long *length, char *is_null, char *error) {
    int n;
    (void)initid;
    (void)args;
    *is_null = 0;
    *error = 0;
    n = snprintf(result, 255, "secure_db_fields %s; MCEN1 AES-256-GCM + HMAC-SHA256", SDF_VERSION);
    *length = (unsigned long)(n > 0 ? n : 0);
    return result;
}

sdf_udf_init_result_t secure_db_fields_is_valid_envelope_init(UDF_INIT *initid, UDF_ARGS *args,
                                                              char *message) {
    return sdf_init_no_state(initid, args, message, 1, "secure_db_fields_is_valid_envelope(blob)",
                             1);
}

long long secure_db_fields_is_valid_envelope(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                                             char *error) {
    (void)initid;
    *error = 0;
    if (!args->args[0]) {
        *is_null = 1;
        return 0;
    }
    *is_null = 0;
    return sdf_is_valid_envelope((const unsigned char *)args->args[0], (size_t)args->lengths[0])
               ? 1
               : 0;
}

sdf_udf_init_result_t secure_db_fields_envelope_key_id_init(UDF_INIT *initid, UDF_ARGS *args,
                                                            char *message) {
    return sdf_init_no_state(initid, args, message, 1, "secure_db_fields_envelope_key_id(blob)",
                             11);
}

long long secure_db_fields_envelope_key_id(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                                           char *error) {
    uint32_t key_id = 0;
    char err[SDF_MAX_ERR];
    (void)initid;
    *error = 0;
    if (!args->args[0]) {
        *is_null = 1;
        return 0;
    }
    if (sdf_parse_key_id((const unsigned char *)args->args[0], (size_t)args->lengths[0], &key_id,
                         err, sizeof(err)) != SDF_OK) {
        *is_null = 1;
        return 0;
    }
    *is_null = 0;
    return (long long)key_id;
}

sdf_udf_init_result_t secure_db_fields_decrypt_init(UDF_INIT *initid, UDF_ARGS *args,
                                                    char *message) {
    return sdf_init_state(initid, args, message, 2, "secure_db_fields_decrypt(envelope, aad)",
                          1024 * 1024 * 16);
}

char *secure_db_fields_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result,
                               unsigned long *length, char *is_null, char *error) {
    sdf_mysql_state *state = (sdf_mysql_state *)initid->ptr;
    unsigned char *out = NULL;
    size_t out_len = 0;
    uint32_t key_id = 0;
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)result;
    *error = 0;
    if (!args->args[0] || !args->args[1]) {
        *is_null = 1;
        return NULL;
    }
    st = sdf_parse_key_id((const unsigned char *)args->args[0], (size_t)args->lengths[0], &key_id,
                          err, sizeof(err));
    if (st != SDF_OK) {
        *is_null = 1;
        return NULL;
    }
    st = sdf_mysql_cached_encryption_key(state, key_id, err, sizeof(err));
    if (st != SDF_OK) {
        if (st == SDF_ERR_KEY)
            *error = 1;
        *is_null = 1;
        return NULL;
    }
    st = sdf_decrypt_aes_256_gcm((const unsigned char *)args->args[0], (size_t)args->lengths[0],
                                 state->enc_key, sizeof(state->enc_key),
                                 (const unsigned char *)args->args[1], (size_t)args->lengths[1],
                                 &out, &out_len, err, sizeof(err));
    if (st != SDF_OK) {
        *is_null = 1;
        return NULL;
    }
    if (!sdf_mysql_ensure_out(state, (unsigned long)out_len)) {
        sdf_secure_clear(out, out_len);
        free(out);
        *error = 1;
        *is_null = 1;
        return NULL;
    }
    memcpy(state->out, out, out_len);
    sdf_secure_clear(out, out_len);
    free(out);
    *length = (unsigned long)out_len;
    *is_null = 0;
    return state->out;
}

void secure_db_fields_decrypt_deinit(UDF_INIT *initid) {
    secure_db_fields_deinit(initid);
}

sdf_udf_init_result_t secure_db_fields_decrypt_field_init(UDF_INIT *initid, UDF_ARGS *args,
                                                          char *message) {
    return sdf_init_state(
        initid, args, message, 4,
        "secure_db_fields_decrypt_field(envelope, table_name, column_name, row_uid)",
        1024 * 1024 * 16);
}

char *secure_db_fields_decrypt_field(UDF_INIT *initid, UDF_ARGS *args, char *result,
                                     unsigned long *length, char *is_null, char *error) {
    sdf_mysql_state *state = (sdf_mysql_state *)initid->ptr;
    unsigned long aad_len;
    char *aad;
    (void)result;
    *error = 0;
    if (!args->args[0] || !args->args[1] || !args->args[2] || !args->args[3] ||
        args->lengths[3] != SDF_ROW_UID_BYTES) {
        *is_null = 1;
        return NULL;
    }
    if (args->lengths[1] > UINT32_MAX || args->lengths[2] > UINT32_MAX ||
        args->lengths[1] > ULONG_MAX - args->lengths[2] ||
        args->lengths[1] + args->lengths[2] > ULONG_MAX - 28) {
        *is_null = 1;
        return NULL;
    }
    aad_len = 4 + 4 + args->lengths[1] + 4 + args->lengths[2] + SDF_ROW_UID_BYTES;
    if (!sdf_mysql_ensure_scratch(state, aad_len)) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }
    aad = state->scratch;
    memcpy(aad, "SDF1", 4);
    sdf_mysql_u32be_write(aad + 4, (uint32_t)args->lengths[1]);
    memcpy(aad + 8, args->args[1], args->lengths[1]);
    sdf_mysql_u32be_write(aad + 8 + args->lengths[1], (uint32_t)args->lengths[2]);
    memcpy(aad + 12 + args->lengths[1], args->args[2], args->lengths[2]);
    memcpy(aad + 12 + args->lengths[1] + args->lengths[2], args->args[3], SDF_ROW_UID_BYTES);

    {
        unsigned char *out = NULL;
        size_t out_len = 0;
        uint32_t key_id = 0;
        char err[SDF_MAX_ERR];
        sdf_status st = sdf_parse_key_id((const unsigned char *)args->args[0],
                                         (size_t)args->lengths[0], &key_id, err, sizeof(err));
        if (st == SDF_OK)
            st = sdf_mysql_cached_encryption_key(state, key_id, err, sizeof(err));
        if (st == SDF_OK) {
            st = sdf_decrypt_aes_256_gcm((const unsigned char *)args->args[0],
                                         (size_t)args->lengths[0], state->enc_key,
                                         sizeof(state->enc_key), (const unsigned char *)aad,
                                         (size_t)aad_len, &out, &out_len, err, sizeof(err));
        }
        if (st != SDF_OK) {
            *is_null = 1;
            if (st == SDF_ERR_KEY)
                *error = 1;
            return NULL;
        }
        if (!sdf_mysql_ensure_out(state, (unsigned long)out_len)) {
            sdf_secure_clear(out, out_len);
            free(out);
            *is_null = 1;
            *error = 1;
            return NULL;
        }
        memcpy(state->out, out, out_len);
        sdf_secure_clear(out, out_len);
        free(out);
        *length = (unsigned long)out_len;
        *is_null = 0;
        *error = 0;
        return state->out;
    }
}

void secure_db_fields_decrypt_field_deinit(UDF_INIT *initid) {
    secure_db_fields_deinit(initid);
}

sdf_udf_init_result_t secure_db_fields_bidx_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    return sdf_init_state(initid, args, message, 2, "secure_db_fields_bidx(value, domain)",
                          SDF_BIDX_BYTES);
}

char *secure_db_fields_bidx(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                            char *is_null, char *error) {
    sdf_mysql_state *state = (sdf_mysql_state *)initid->ptr;
    unsigned char out[SDF_BIDX_BYTES];
    char domain[96];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)result;
    *error = 0;
    if (!args->args[0] || !args->args[1]) {
        *is_null = 1;
        return NULL;
    }
    if (args->lengths[1] >= sizeof(domain)) {
        *is_null = 1;
        return NULL;
    }
    memcpy(domain, args->args[1], args->lengths[1]);
    domain[args->lengths[1]] = '\0';
    st = sdf_mysql_cached_bidx_key(state, domain, err, sizeof(err));
    if (st == SDF_OK) {
        st = sdf_blind_index((const unsigned char *)args->args[0], (size_t)args->lengths[0],
                             state->bidx_key, sizeof(state->bidx_key), out, err, sizeof(err));
    }
    if (st != SDF_OK) {
        if (st == SDF_ERR_KEY)
            *error = 1;
        *is_null = 1;
        return NULL;
    }
    if (!sdf_mysql_ensure_out(state, SDF_BIDX_BYTES)) {
        *error = 1;
        *is_null = 1;
        return NULL;
    }
    memcpy(state->out, out, SDF_BIDX_BYTES);
    *length = SDF_BIDX_BYTES;
    *is_null = 0;
    return state->out;
}

void secure_db_fields_bidx_deinit(UDF_INIT *initid) {
    secure_db_fields_deinit(initid);
}

sdf_udf_init_result_t secure_phone_bidx_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    return sdf_init_state(initid, args, message, 1, "secure_phone_bidx(e164)", SDF_BIDX_BYTES);
}

char *secure_phone_bidx(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                        char *is_null, char *error) {
    sdf_mysql_state *state = (sdf_mysql_state *)initid->ptr;
    unsigned char out[SDF_BIDX_BYTES];
    char err[SDF_MAX_ERR];
    sdf_status st;
    (void)result;
    *error = 0;
    if (!args->args[0]) {
        *is_null = 1;
        return NULL;
    }
    st = sdf_mysql_cached_bidx_key(state, "PHONE", err, sizeof(err));
    if (st == SDF_OK) {
        st = sdf_phone_exact_bidx((const unsigned char *)args->args[0], (size_t)args->lengths[0],
                                  state->bidx_key, sizeof(state->bidx_key), out, err, sizeof(err));
    }
    if (st != SDF_OK) {
        if (st == SDF_ERR_KEY)
            *error = 1;
        *is_null = 1;
        return NULL;
    }
    if (!sdf_mysql_ensure_out(state, SDF_BIDX_BYTES)) {
        *error = 1;
        *is_null = 1;
        return NULL;
    }
    memcpy(state->out, out, SDF_BIDX_BYTES);
    *length = SDF_BIDX_BYTES;
    *is_null = 0;
    return state->out;
}

void secure_phone_bidx_deinit(UDF_INIT *initid) {
    secure_db_fields_deinit(initid);
}

sdf_udf_init_result_t secure_phone_prefix_bidx_init(UDF_INIT *initid, UDF_ARGS *args,
                                                    char *message) {
    sdf_mysql_state *state;
    if (args->arg_count != 2) {
        snprintf(message, 255,
                 "secure_phone_prefix_bidx(e164, prefix_digits) takes exactly 2 arguments");
        return 1;
    }
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = INT_RESULT;
    state = sdf_mysql_state_new();
    if (!state) {
        snprintf(message, 255, "out of memory");
        return 1;
    }
    initid->ptr = (char *)state;
    initid->maybe_null = 1;
    initid->const_item = 0;
    initid->max_length = SDF_BIDX_BYTES;
    return 0;
}

char *secure_phone_prefix_bidx(UDF_INIT *initid, UDF_ARGS *args, char *result,
                               unsigned long *length, char *is_null, char *error) {
    sdf_mysql_state *state = (sdf_mysql_state *)initid->ptr;
    unsigned char out[SDF_BIDX_BYTES];
    char domain[32];
    char err[SDF_MAX_ERR];
    long long prefix_ll = 0;
    unsigned int prefix_digits;
    sdf_status st;
    (void)result;
    *error = 0;
    if (!args->args[0] || !args->args[1]) {
        *is_null = 1;
        return NULL;
    }
    memcpy(&prefix_ll, args->args[1], sizeof(prefix_ll));
    if (prefix_ll <= 0 || prefix_ll > 15) {
        *is_null = 1;
        return NULL;
    }
    prefix_digits = (unsigned int)prefix_ll;
    snprintf(domain, sizeof(domain), "PHONE_P%u", prefix_digits);
    st = sdf_mysql_cached_bidx_key(state, domain, err, sizeof(err));
    if (st == SDF_OK) {
        st = sdf_phone_prefix_bidx((const unsigned char *)args->args[0], (size_t)args->lengths[0],
                                   prefix_digits, state->bidx_key, sizeof(state->bidx_key), out,
                                   err, sizeof(err));
    }
    if (st != SDF_OK) {
        if (st == SDF_ERR_KEY)
            *error = 1;
        *is_null = 1;
        return NULL;
    }
    if (!sdf_mysql_ensure_out(state, SDF_BIDX_BYTES)) {
        *error = 1;
        *is_null = 1;
        return NULL;
    }
    memcpy(state->out, out, SDF_BIDX_BYTES);
    *length = SDF_BIDX_BYTES;
    *is_null = 0;
    return state->out;
}

void secure_phone_prefix_bidx_deinit(UDF_INIT *initid) {
    secure_db_fields_deinit(initid);
}
