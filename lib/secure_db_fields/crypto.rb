# frozen_string_literal: true

module SecureDBFields
  module Crypto
    module_function

    ENVELOPE_MAGIC = "MCEN".b
    KEY_BYTES = 32
    BIDX_BYTES = 32

    def encrypt(value, key:, aad:, key_id: 1)
      raise ArgumentError, "value must not be nil" if value.nil?
      Native.encrypt(value.to_s, assert_key!(key), aad.to_s, Integer(key_id))
    end

    def decrypt(envelope, key:, aad:)
      raise ArgumentError, "envelope must not be nil" if envelope.nil?
      Native.decrypt(envelope.to_s, assert_key!(key), aad.to_s)
    end

    def key_id(envelope)
      Native.key_id(envelope.to_s)
    end

    def valid_envelope?(envelope)
      return false if envelope.nil?
      Native.valid_envelope?(envelope.to_s)
    end

    def blind_index(value, key:)
      raise ArgumentError, "value must not be nil" if value.nil?
      Native.blind_index(value.to_s, assert_key!(key))
    end

    def phone_blind_index(e164, key:)
      Native.phone_blind_index(e164.to_s, assert_key!(key))
    end

    def phone_prefix_blind_index(e164, prefix_digits:, key:)
      Native.phone_prefix_blind_index(e164.to_s, Integer(prefix_digits), assert_key!(key))
    end

    def encrypt_raw(value, key, aad, key_id = 1)
      Native.encrypt(value, key, aad, key_id)
    end

    def decrypt_raw(envelope, key, aad)
      Native.decrypt(envelope, key, aad)
    end

    def blind_index_raw(value, key)
      Native.blind_index(value, key)
    end

    def phone_blind_index_raw(e164, key)
      Native.phone_blind_index(e164, key)
    end

    def phone_prefix_blind_index_raw(e164, prefix_digits, key)
      Native.phone_prefix_blind_index(e164, prefix_digits, key)
    end

    def encrypt_many(values, key:, aads:, key_id: 1)
      Native.encrypt_many(values, assert_key!(key), aads, Integer(key_id))
    end

    def decrypt_many(envelopes, key:, aads:)
      Native.decrypt_many(envelopes, assert_key!(key), aads)
    end

    def blind_index_many(values, key:)
      Native.blind_index_many(values, assert_key!(key))
    end

    def blind_index_many_packed(values, key:)
      Native.blind_index_many_packed(values, assert_key!(key))
    end

    def phone_blind_index_many(e164_values, key:)
      Native.phone_blind_index_many(e164_values, assert_key!(key))
    end

    def phone_blind_index_many_packed(e164_values, key:)
      Native.phone_blind_index_many_packed(e164_values, assert_key!(key))
    end

    def phone_prefix_blind_index_many(e164_values, prefix_digits:, key:)
      Native.phone_prefix_blind_index_many(e164_values, Integer(prefix_digits), assert_key!(key))
    end

    def phone_prefix_blind_index_many_packed(e164_values, prefix_digits:, key:)
      Native.phone_prefix_blind_index_many_packed(e164_values, Integer(prefix_digits), assert_key!(key))
    end

    def hex_decode_key(hex)
      Native.hex_decode_key(hex.to_s)
    end

    def assert_key!(key)
      key = key.to_s
      raise KeyError, "key must be exactly #{KEY_BYTES} bytes" unless key.bytesize == KEY_BYTES
      key
    end

    def aad(table, column, secure_row_uid)
      uid = secure_row_uid.to_s
      raise ArgumentError, "secure_row_uid must be 16 bytes" unless uid.bytesize == 16
      table = table.to_s.b
      column = column.to_s.b
      raise ArgumentError, "table name is too long" if table.bytesize > 0xffffffff
      raise ArgumentError, "column name is too long" if column.bytesize > 0xffffffff
      "SDF1".b + [table.bytesize].pack("N") + table + [column.bytesize].pack("N") + column + uid.b
    end
  end
end
