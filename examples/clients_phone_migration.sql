-- MySQL 5.7 physical columns for clients.phone.
ALTER TABLE clients
  ADD COLUMN secure_row_uid BINARY(16) NULL,
  ADD COLUMN phone_enc VARBINARY(512) NULL,
  ADD COLUMN phone_bidx BINARY(32) NULL,
  ADD INDEX idx_clients_phone_bidx (phone_bidx);

-- Add prefix columns only after query inventory.
-- ALTER TABLE clients ADD COLUMN phone_bidx_p7 BINARY(32) NULL, ADD INDEX idx_clients_phone_bidx_p7 (phone_bidx_p7);
