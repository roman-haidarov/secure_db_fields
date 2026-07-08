# secure_db_fields MySQL UDF

This UDF is the DB-side reader/search-token helper for MySQL 5.7. It is intentionally
narrow: decrypt for admin projections and compute blind-index tokens for declared
search modes. It does not normalize phone input; pass canonical E.164 values.

## Compatibility

Target: MySQL 5.7. The package ships a minimal 5.7 ABI shim for build environments where `mysql_config` or MySQL headers are unavailable. Do not use MySQL 8-only functional-index designs with this UDF; bidx values must be physical columns populated by Ruby/backfill.

## Build

```bash
cd mysql_udf
make
sudo make install
mysql < sql/install.sql
```

If `mysql_config` is not available, build with the minimal MySQL 5.7 ABI shim:

```bash
make abi57
sudo install -m 0755 secure_db_fields_mysql.so /path/to/mysql/plugin_dir/
```

## Keys

The UDF reads keys from `/etc/secure_db_fields/keys.env` or from
`SECURE_DB_FIELDS_KEY_FILE` when that environment variable is visible to mysqld.
Never pass keys as SQL arguments.

Example:

```env
SDF_ACTIVE_KEY_ID=1
SDF_ENC_KEY_1_HEX=0000000000000000000000000000000000000000000000000000000000000001
SDF_BIDX_PHONE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000002
SDF_BIDX_PHONE_P7_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000003
```

## Functions

- `secure_db_fields_version()`
- `secure_db_fields_is_valid_envelope(blob)`
- `secure_db_fields_envelope_key_id(blob)`
- `secure_db_fields_decrypt(blob, aad)`
- `secure_db_fields_decrypt_field(blob, table_name, column_name, row_uid)`
- `secure_db_fields_bidx(value, domain)`
- `secure_phone_bidx(e164)`
- `secure_phone_prefix_bidx(e164, prefix_digits)`
