
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
