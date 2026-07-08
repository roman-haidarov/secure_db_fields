# frozen_string_literal: true

require_relative "test_helper"

class SecureDBFieldsCryptoTest < Minitest::Test
  KEY = "a" * 32
  BIDX_KEY = "b" * 32

  def test_encrypt_decrypt_roundtrip
    uid = SecureRandom.random_bytes(16)
    aad = SecureDBFields::Crypto.aad("clients", "phone", uid)
    enc = SecureDBFields::Crypto.encrypt("+77771234567", key: KEY, aad: aad, key_id: 7)

    assert SecureDBFields::Crypto.valid_envelope?(enc)
    assert_equal 7, SecureDBFields::Crypto.key_id(enc)
    assert_equal "+77771234567", SecureDBFields::Crypto.decrypt(enc, key: KEY, aad: aad)
  end

  def test_wrong_aad_fails
    uid = SecureRandom.random_bytes(16)
    aad = SecureDBFields::Crypto.aad("clients", "phone", uid)
    enc = SecureDBFields::Crypto.encrypt("secret", key: KEY, aad: aad, key_id: 1)

    assert_raises(SecureDBFields::AuthenticationError) do
      SecureDBFields::Crypto.decrypt(enc, key: KEY, aad: "clients.phone:wrong")
    end
  end

  def test_blind_index_is_stable_and_binary_32
    a = SecureDBFields::Crypto.blind_index("value", key: BIDX_KEY)
    b = SecureDBFields::Crypto.blind_index("value", key: BIDX_KEY)
    c = SecureDBFields::Crypto.blind_index("other", key: BIDX_KEY)

    assert_equal 32, a.bytesize
    assert_equal a, b
    refute_equal a, c
  end

  def test_phone_validation_and_indexes
    assert SecureDBFields::Phone.canonical_e164?("+77771234567")
    refute SecureDBFields::Phone.canonical_e164?("8 777 123 45 67")

    exact = SecureDBFields::Crypto.phone_blind_index("+77771234567", key: BIDX_KEY)
    prefix = SecureDBFields::Crypto.phone_prefix_blind_index("+77771234567", prefix_digits: 4, key: BIDX_KEY)

    assert_equal 32, exact.bytesize
    assert_equal 32, prefix.bytesize
    refute_equal exact, prefix
  end

  def test_non_e164_phone_rejected
    assert_raises(SecureDBFields::Error) do
      SecureDBFields::Crypto.phone_blind_index("87771234567", key: BIDX_KEY)
    end
  end

  def test_hex_decode_key
    key = SecureDBFields::Crypto.hex_decode_key("00" * 32)
    assert_equal 32, key.bytesize
    assert_equal "\x00".b * 32, key
  end
end
