-- Example physical schema for clients.phone.
ALTER TABLE clients
  ADD COLUMN secure_row_uid BINARY(16) NULL,
  ADD COLUMN phone_enc VARBINARY(512) NULL,
  ADD COLUMN phone_bidx BINARY(32) NULL,
  ADD INDEX idx_clients_phone_bidx (phone_bidx);

-- Prefix indexes are exceptional and must match the inventory of real queries.
-- ALTER TABLE clients ADD COLUMN phone_bidx_p7 BINARY(32) NULL, ADD INDEX idx_clients_phone_bidx_p7(phone_bidx_p7);

-- Readable projection. Do not use this view for indexed search by plaintext phone.
CREATE OR REPLACE VIEW admin_clients_readable AS
SELECT
  id,
  secure_db_fields_decrypt_field(phone_enc, 'clients', 'phone', secure_row_uid) AS phone,
  created_at
FROM clients;

-- Indexed exact search template.
SELECT
  id,
  secure_db_fields_decrypt_field(phone_enc, 'clients', 'phone', secure_row_uid) AS phone,
  created_at
FROM clients
WHERE phone_bidx = secure_phone_bidx('+77771234567');
