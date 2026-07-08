# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"

class SecureDBFieldsKeyringTest < Minitest::Test
  def test_keyring_loads_keys
    file = File.join(Dir.mktmpdir, "keys.env")
    File.write(file, File.read(File.expand_path("../examples/keys.env.example", __dir__)))
    File.chmod(0o600, file)
    keyring = SecureDBFields::Keyring.new(file)

    assert_equal 1, keyring.active_key_id
    assert_equal 32, keyring.encryption_key(1).bytesize
    assert_equal 32, keyring.blind_index_key("PHONE").bytesize
  end

  def test_keyring_rejects_open_permissions
    file = File.join(Dir.mktmpdir, "keys.env")
    File.write(file, "SDF_ENC_KEY_HEX=#{'00' * 32}\n")
    File.chmod(0o644, file)

    assert_raises(SecureDBFields::KeyError) do
      SecureDBFields::Keyring.new(file)
    end
  end
end
