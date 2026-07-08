-- MySQL 5.7 UDF hot-path sample for DB-side decrypt.
-- First generate variables with the Ruby helper:
--   bundle exec ruby samples/mysql_udf_prepare_decrypt_payload.rb
-- Then in mysql console:
--   source /tmp/secure_db_fields_mysql_decrypt_payload.sql;
--   source samples/mysql_udf_decrypt_hot_path.sql;
--   CALL sdf_decrypt_hot_loop(500000);
-- Console 2:
--   sample $(pgrep -n mysqld) 35 -f /tmp/secure_db_fields_mysql_decrypt.sample
--   filtercalltree /tmp/secure_db_fields_mysql_decrypt.sample | grep -E 'secure_db_fields_decrypt|sdf_parse_key_id|sdf_load_encryption_key|sdf_load_key_from_env_file|sdf_decrypt_aes_256_gcm|EVP_Decrypt|AES|GCM|sdf_secure_clear' | head -300
--
-- Expected hot C path:
--   secure_db_fields_decrypt -> sdf_parse_key_id -> sdf_load_encryption_key
--   -> sdf_decrypt_aes_256_gcm -> EVP AES-256-GCM auth/decrypt

DROP PROCEDURE IF EXISTS sdf_decrypt_hot_loop;
DELIMITER //
CREATE PROCEDURE sdf_decrypt_hot_loop(IN iterations INT)
BEGIN
  DECLARE i INT DEFAULT 0;
  DECLARE plain VARBINARY(1024);
  IF @sdf_sample_envelope IS NULL OR @sdf_sample_aad IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'run source /tmp/secure_db_fields_mysql_decrypt_payload.sql first';
  END IF;
  WHILE i < iterations DO
    SET plain = secure_db_fields_decrypt(@sdf_sample_envelope, @sdf_sample_aad);
    SET i = i + 1;
  END WHILE;
  SELECT plain AS last_plaintext, @sdf_sample_plaintext AS expected_plaintext, iterations AS iterations;
END//
DELIMITER ;
