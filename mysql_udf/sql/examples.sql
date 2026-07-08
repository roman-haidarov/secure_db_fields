ALTER TABLE clients
  ADD COLUMN secure_row_uid BINARY(16) NULL,
  ADD COLUMN phone_enc VARBINARY(512) NULL,
  ADD COLUMN phone_bidx BINARY(32) NULL,
  ADD INDEX idx_clients_phone_bidx (phone_bidx);


CREATE OR REPLACE VIEW admin_clients_readable AS
SELECT
  id,
  secure_db_fields_decrypt_field(phone_enc, 'clients', 'phone', secure_row_uid) AS phone,
  created_at
FROM clients;

SELECT
  id,
  secure_db_fields_decrypt_field(phone_enc, 'clients', 'phone', secure_row_uid) AS phone,
  created_at
FROM clients
WHERE phone_bidx = secure_phone_bidx('+77771234567');
