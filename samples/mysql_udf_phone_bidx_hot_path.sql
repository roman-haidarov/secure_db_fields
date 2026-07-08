-- MySQL 5.7 UDF hot-path sample for exact phone blind indexes.
-- Console 1:
--   mysql <database> < samples/mysql_udf_phone_bidx_hot_path.sql
--   CALL sdf_phone_bidx_hot_loop(500000);
-- Console 2:
--   sample $(pgrep -n mysqld) 35 -f /tmp/secure_db_fields_mysql_phone_bidx.sample
--   filtercalltree /tmp/secure_db_fields_mysql_phone_bidx.sample | grep -E 'secure_phone_bidx|sdf_phone_exact_bidx|sdf_is_canonical_e164|sdf_blind_index|HMAC|SHA256|EVP_sha256|sdf_load_bidx_key|sdf_load_key_from_env_file' | head -260
--
-- Expected hot C path:
--   secure_phone_bidx -> sdf_load_bidx_key -> sdf_phone_exact_bidx
--   -> sdf_is_canonical_e164 -> sdf_blind_index -> HMAC-SHA256

DROP PROCEDURE IF EXISTS sdf_phone_bidx_hot_loop;
DELIMITER //
CREATE PROCEDURE sdf_phone_bidx_hot_loop(IN iterations INT)
BEGIN
  DECLARE i INT DEFAULT 0;
  DECLARE token VARBINARY(32);
  WHILE i < iterations DO
    SET token = secure_phone_bidx('+77771234567');
    SET i = i + 1;
  END WHILE;
  SELECT HEX(token) AS last_phone_bidx, iterations AS iterations;
END//
DELIMITER ;
