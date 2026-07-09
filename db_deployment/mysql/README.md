# secure_db_fields MySQL DBA bundle

This archive is produced on an application host with:

```bash
secure_db_fields db package mysql --output secure_db_fields-mysql.tar.gz --force
```

The archive contains the MySQL UDF source and the same `keys.env` contract used by the application. Copy the archive to the MySQL 5.7 host, extract it, then run:

```bash
make verify
make doctor MYSQL_DEFAULTS_FILE=/root/secure-db-fields-mysql.cnf MYSQL_SOCKET=/run/mysqld/mysqld.sock
make install MYSQL_DEFAULTS_FILE=/root/secure-db-fields-mysql.cnf MYSQL_SOCKET=/run/mysqld/mysqld.sock
make enable MYSQL_DEFAULTS_FILE=/root/secure-db-fields-mysql.cnf MYSQL_SOCKET=/run/mysqld/mysqld.sock
make status MYSQL_DEFAULTS_FILE=/root/secure-db-fields-mysql.cnf MYSQL_SOCKET=/run/mysqld/mysqld.sock
```

`make install` installs `etc/secure_db_fields/keys.env` from this bundle to `/etc/secure_db_fields/keys.env` with `0640 root:mysql` permissions.

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
