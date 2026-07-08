# frozen_string_literal: true

require "securerandom"
require "secure_db_fields"

keyring = SecureDBFields::Keyring.new(File.expand_path("keys.env.example", __dir__))
uid = SecureRandom.random_bytes(16)
phone = "+77771234567"

aad = SecureDBFields::Crypto.aad("clients", "phone", uid)
phone_enc = SecureDBFields::Crypto.encrypt(phone, key: keyring.encryption_key(1), aad: aad, key_id: 1)
phone_bidx = SecureDBFields::Crypto.phone_blind_index(phone, key: keyring.blind_index_key("PHONE"))

puts SecureDBFields::Crypto.decrypt(phone_enc, key: keyring.encryption_key(1), aad: aad)
puts phone_bidx.unpack1("H*")
