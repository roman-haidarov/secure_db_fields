# frozen_string_literal: true

require_relative "test_helper"
require "rubygems/package"
require "tmpdir"
require "zlib"
require "secure_db_fields/db_deployment"

class SecureDBFieldsDBDeploymentTest < Minitest::Test
  def test_package_creates_key_contract_and_embeds_it
    Dir.mktmpdir do |dir|
      output = File.join(dir, "secure_db_fields-mysql.tar.gz")
      keys = File.join(dir, "keys.env")

      status = SecureDBFields::DBDeployment::CLI.run(["package", "mysql", "--output", output, "--keys", keys, "--force"])

      assert_equal 0, status
      assert File.file?(output)
      assert File.file?(keys)
      assert_equal 0, File.stat(keys).mode & 0o077
      assert_match(/SDF_ACTIVE_KEY_ID=1/, File.read(keys))

      entries = tar_entries(output)
      bundle = "secure_db_fields-mysql-#{SecureDBFields::VERSION}"
      assert_includes entries.keys, "#{bundle}/etc/secure_db_fields/keys.env"
      assert_equal File.read(keys), entries.fetch("#{bundle}/etc/secure_db_fields/keys.env")
      assert_includes entries.fetch("#{bundle}/SHA256SUMS"), "etc/secure_db_fields/keys.env"
    end
  end

  def test_package_rejects_placeholder_key_contract
    Dir.mktmpdir do |dir|
      output = File.join(dir, "secure_db_fields-mysql.tar.gz")
      keys = File.join(dir, "keys.env")
      File.write(keys, "SDF_ACTIVE_KEY_ID=1\nSDF_ENC_KEY_HEX=<same 64 hex chars as app-host>\n")
      File.chmod(0o600, keys)

      status = SecureDBFields::DBDeployment::CLI.run(["package", "mysql", "--output", output, "--keys", keys, "--force"])

      assert_equal 2, status
      refute File.exist?(output)
    end
  end

  private

  def tar_entries(path)
    result = {}
    Zlib::GzipReader.open(path) do |gz|
      Gem::Package::TarReader.new(gz) do |tar|
        tar.each do |entry|
          result[entry.full_name] = entry.read if entry.file?
        end
      end
    end
    result
  end
end
