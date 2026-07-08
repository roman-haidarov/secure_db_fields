# frozen_string_literal: true

module SecureDBFields
  module Crypto
    module_function

    ENVELOPE_MAGIC = "MCEN".b
    KEY_BYTES = 32
    BIDX_BYTES = 32

    def encrypt(value, key:, aad:, key_id: 1)
      raise ArgumentError, "value must not be nil" if value.nil?
      Native.encrypt(value.to_s.b, assert_key!(key), aad.to_s.b, Integer(key_id))
    end

    def decrypt(envelope, key:, aad:)
      raise ArgumentError, "envelope must not be nil" if envelope.nil?
      Native.decrypt(envelope.to_s.b, assert_key!(key), aad.to_s.b)
    end

    def key_id(envelope)
      Native.key_id(envelope.to_s.b)
    end

    def valid_envelope?(envelope)
      return false if envelope.nil?
      Native.valid_envelope?(envelope.to_s.b)
    end

    def blind_index(value, key:)
      raise ArgumentError, "value must not be nil" if value.nil?
      Native.blind_index(value.to_s.b, assert_key!(key))
    end

    def phone_blind_index(e164, key:)
      Native.phone_blind_index(e164.to_s.b, assert_key!(key))
    end

    def phone_prefix_blind_index(e164, prefix_digits:, key:)
      Native.phone_prefix_blind_index(e164.to_s.b, Integer(prefix_digits), assert_key!(key))
    end

    def hex_decode_key(hex)
      Native.hex_decode_key(hex.to_s)
    end

    def assert_key!(key)
      key = key.to_s.b
      raise KeyError, "key must be exactly #{KEY_BYTES} bytes" unless key.bytesize == KEY_BYTES
      key
    end

    def aad(table, column, secure_row_uid)
      uid = secure_row_uid.to_s.b
      raise ArgumentError, "secure_row_uid must be 16 bytes" unless uid.bytesize == 16
      "#{table}.#{column}:".b + uid
    end
  end
end
