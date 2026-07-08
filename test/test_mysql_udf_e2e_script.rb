# frozen_string_literal: true

require "minitest/autorun"

class SecureDBFieldsMysqlUdfE2EScriptTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  SCRIPT = File.join(ROOT, "mysql_udf/test/run_e2e.sh")

  def source
    @source ||= File.binread(SCRIPT).force_encoding(Encoding::UTF_8)
  end

  def test_is_valid_bash
    assert system("bash", "-n", SCRIPT), "run_e2e.sh must pass bash syntax validation"
  end

  def test_pins_mysql_57_and_uses_database_host_bundle
    assert_match(/DEFAULT_MYSQL_IMAGE="mysql:5\.7\.44@sha256:[0-9a-f]{64}"/, source)
    assert_includes source, "gem build secure_db_fields.gemspec"
    assert_includes source, "gem unpack"
    assert_includes source, "db package mysql"
    assert_includes source, "make verify"
    assert_includes source, "make doctor"
    assert_includes source, "make install"
    assert_includes source, "make enable"
    assert_includes source, "make status"
    assert_includes source, "CONFIRM=REMOVE_SECURE_DB_FIELDS make uninstall"
  end

  def test_exercises_udf_functions_and_indexed_search
    assert_includes source, "secure_db_fields_decrypt_field"
    assert_includes source, "secure_phone_bidx"
    assert_includes source, "secure_phone_prefix_bidx"
    assert_includes source, "admin.clients_readable"
    assert_includes source, "EXPLAIN SELECT id FROM app.clients WHERE phone_bidx = secure_phone_bidx"
    assert_includes source, "idx_clients_phone_bidx"
    assert_includes source, "idx_clients_phone_bidx_p7"
  end

  def test_deployment_bundle_sources_are_in_gemspec
    gemspec = File.read(File.join(ROOT, "secure_db_fields.gemspec"))
    assert_includes gemspec, "db_deployment/**/*"
    assert_includes gemspec, "exe/*"
    assert_includes gemspec, "spec.executables"
  end
end
