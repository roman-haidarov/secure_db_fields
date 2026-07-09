# Implementation notes

## Compatibility

- Ruby: `>= 2.7.1`. No `Data.define`, no Ruby 3-only syntax, no required keyword-argument forwarding.
- MySQL: `5.7`. No functional indexes, no generated bidx columns via UDF, no MySQL 8-specific UDF assumptions.
- OpenSSL: AES-256-GCM via libcrypto EVP APIs available on common MySQL 5.7 hosts.

## Locked scope

This package implements the lean version of the final decision:

- explicit field configuration in the host app, not a DSL/codegen platform;
- Ruby API for encryption/decryption/blind indexes;
- C core shared by Ruby and MySQL UDF;
- MySQL UDF SQL install/uninstall/examples;
- physical `*_bidx` columns only.

## Envelope format MCEN1

```text
magic      4 bytes  "MCEN"
version    1 byte   1
alg_id     1 byte   1 = AES-256-GCM
key_id     4 bytes  big-endian uint32
nonce     12 bytes  random GCM nonce
tag       16 bytes  GCM auth tag
ciphertext N bytes
```

AAD is not stored. It must be reconstructed as:

```text
<table>.<column>:<16 raw bytes secure_row_uid>
```

## Key file format

```env
SDF_ACTIVE_KEY_ID=1
SDF_ENC_KEY_1_HEX=<64 hex chars>
SDF_BIDX_PHONE_KEY_HEX=<64 hex chars>
SDF_BIDX_PHONE_P7_KEY_HEX=<64 hex chars>
```

## Admin SQL boundary

Readable views are for projection. Indexed search must use bidx predicates or stored procedures.

## Hot-path implementation notes (0.1.1)

The Ruby extension has separate scalar and batch paths:

- Scalar `blind_index` keeps the simple shared C-core `sdf_blind_index` path.
- Batch bidx methods use a fixed HMAC-SHA256 implementation in the Ruby extension:
  the 64-byte ipad/opad SHA256 states are precomputed once per batch, then copied
  per value. This avoids `HMAC_CTX_new/free/reset` and repeated pad hashing.
- Packed batch methods (`*_many_packed`) return one binary String containing
  concatenated 32-byte digests, avoiding Array + String-per-digest allocation.
- Ruby encrypt/decrypt paths allocate the destination Ruby String first and call
  `sdf_*_aes_256_gcm_into`, avoiding native `malloc -> rb_str_new copy -> free`.

The hot-path notes below describe the 0.1.1 implementation-level optimizations. Version 0.1.2 adds the DBA bundle key-contract flow without changing the envelope format.
