# secure_db_fields

`secure_db_fields` is a narrow field-level encryption layer for Ruby/Rails + MySQL 5.7.

Compatibility target: Ruby >= 2.7.1 and MySQL 5.7. The gem intentionally avoids Ruby 3-only language/API features and the UDF avoids MySQL 8-only features such as functional indexes.
It follows the locked design from `docs/final_decision.md`:

- AES-256-GCM randomized envelope for confidential values.
- HMAC-SHA256 blind indexes for exact indexed search.
- Physical `*_bidx` columns, not generated columns.
- MySQL UDFs for admin views/search helpers in DBeaver/DataGrip.
- Keys outside the database and never passed as SQL arguments.
- No `pq_crypto`, no OPE/FPE/range-preserving encryption, no transparent arbitrary `LIKE`.

## Threat model

Protected: raw table / SQL dump / physical column data leaked without key files.

Not protected: DB host compromise, key-file compromise, or authorized admin access to decrypt UDF/views.

## Ruby quick start

```ruby
require "secure_db_fields"

keyring = SecureDBFields::Keyring.new("/etc/secure_db_fields/keys.env")
uid = SecureRandom.random_bytes(16)
phone = "+77771234567"

aad = SecureDBFields::Crypto.aad("clients", "phone", uid)
enc = SecureDBFields::Crypto.encrypt(phone, key: keyring.encryption_key(1), aad: aad, key_id: 1)
bidx = SecureDBFields::Crypto.phone_blind_index(phone, key: keyring.blind_index_key("PHONE"))

SecureDBFields::Crypto.decrypt(enc, key: keyring.encryption_key(1), aad: aad)
# => "+77771234567"
```

## MySQL exact search template

```sql
SELECT
  id,
  secure_db_fields_decrypt_field(phone_enc, 'clients', 'phone', secure_row_uid) AS phone,
  created_at
FROM clients
WHERE phone_bidx = secure_phone_bidx('+77771234567');
```

Do not search by plaintext through the decrypt view:

```sql
-- forbidden on large tables: decrypt-scan
SELECT * FROM admin_clients_readable WHERE phone = '+77771234567';
```

## Prefix search

Prefix search is not generic SQL `LIKE`. It is a named search mode with a physical column:

```sql
phone_bidx_p7 BINARY(32), INDEX idx_clients_phone_bidx_p7(phone_bidx_p7)
```

Only add prefix columns confirmed by query inventory. `last4`/suffix is intentionally not part of
the default schema because it has very low cardinality and high leakage.
