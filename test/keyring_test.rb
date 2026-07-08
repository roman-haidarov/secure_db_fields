# frozen_string_literal: true

require_relative "test_helper"

class SecureDBFieldsKeyringTest < Minitest::Test
  def test_keyring_loads_keys
    file = File.expand_path("../examples/keys.env.example", __dir__)
    keyring = SecureDBFields::Keyring.new(file)

    assert_equal 1, keyring.active_key_id
    assert_equal 32, keyring.encryption_key(1).bytesize
    assert_equal 32, keyring.blind_index_key("PHONE").bytesize
  end
end
