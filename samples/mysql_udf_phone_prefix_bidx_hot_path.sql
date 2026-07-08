
DROP PROCEDURE IF EXISTS sdf_phone_prefix_bidx_hot_loop;
DELIMITER //
CREATE PROCEDURE sdf_phone_prefix_bidx_hot_loop(IN iterations INT, IN prefix_digits INT)
BEGIN
  DECLARE i INT DEFAULT 0;
  DECLARE token VARBINARY(32);
  WHILE i < iterations DO
    SET token = secure_phone_prefix_bidx('+77771234567', prefix_digits);
    SET i = i + 1;
  END WHILE;
  SELECT HEX(token) AS last_phone_prefix_bidx, prefix_digits AS prefix_digits, iterations AS iterations;
END//
DELIMITER ;
