ALTER TABLE clients
  ADD COLUMN secure_row_uid BINARY(16) NULL,
  ADD COLUMN phone_enc VARBINARY(512) NULL,
  ADD COLUMN phone_bidx BINARY(32) NULL,
  ADD INDEX idx_clients_phone_bidx (phone_bidx);

