
DROP FUNCTION IF EXISTS secure_db_fields_version;
DROP FUNCTION IF EXISTS secure_db_fields_is_valid_envelope;
DROP FUNCTION IF EXISTS secure_db_fields_envelope_key_id;
DROP FUNCTION IF EXISTS secure_db_fields_decrypt;
DROP FUNCTION IF EXISTS secure_db_fields_decrypt_field;
DROP FUNCTION IF EXISTS secure_db_fields_bidx;
DROP FUNCTION IF EXISTS secure_phone_bidx;
DROP FUNCTION IF EXISTS secure_phone_prefix_bidx;

CREATE FUNCTION secure_db_fields_version RETURNS STRING SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_db_fields_is_valid_envelope RETURNS INTEGER SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_db_fields_envelope_key_id RETURNS INTEGER SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_db_fields_decrypt RETURNS STRING SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_db_fields_decrypt_field RETURNS STRING SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_db_fields_bidx RETURNS STRING SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_phone_bidx RETURNS STRING SONAME 'secure_db_fields_mysql.so';
CREATE FUNCTION secure_phone_prefix_bidx RETURNS STRING SONAME 'secure_db_fields_mysql.so';

SELECT secure_db_fields_version();
