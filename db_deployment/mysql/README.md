# secure_db_fields MySQL DBA bundle

This archive is produced on an application host with:

```bash
secure_db_fields db package mysql --output secure_db_fields-mysql.tar.gz --force
```

Copy the archive to the MySQL 5.7 host, extract it, then run:

```bash
make verify
make doctor
sudo make install
make enable
make status
```

Keys are not included in this archive. The DBA must provision `/etc/secure_db_fields/keys.env`
(or set `SECURE_DB_FIELDS_KEY_FILE` for mysqld) before using decrypt/search UDFs.

Installed SQL functions:

- `secure_db_fields_version()`
- `secure_db_fields_is_valid_envelope(blob)`
- `secure_db_fields_envelope_key_id(blob)`
- `secure_db_fields_decrypt(blob, aad)`
- `secure_db_fields_decrypt_field(blob, table_name, column_name, row_uid)`
- `secure_db_fields_bidx(value, domain)`
- `secure_phone_bidx(e164)`
- `secure_phone_prefix_bidx(e164, prefix_digits)`

The readable-view pattern is display-only. Indexed search must use physical bidx columns.
