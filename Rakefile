# frozen_string_literal: true

require "rake/testtask"
require "rake/extensiontask"

Rake::ExtensionTask.new("secure_db_fields", Gem::Specification.load("secure_db_fields.gemspec")) do |ext|
  ext.lib_dir = "lib/secure_db_fields"
end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.pattern = "test/**/*_test.rb"
end

task default: %i[compile test]
