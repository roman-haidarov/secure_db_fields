
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
