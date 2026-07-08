# frozen_string_literal: true

require_relative "lib/secure_db_fields/version"

Gem::Specification.new do |spec|
  spec.name = "secure_db_fields"
  spec.version = SecureDBFields::VERSION
  spec.authors = ["Roman Khaidarov"]
  spec.email = ["romnhajdarov@gmail.com"]
  spec.summary = "Field-level encryption for Ruby + MySQL 5.7 with blind indexes and DB UDFs"
  spec.description = "A narrow production-oriented field encryption layer: AES-256-GCM envelope, HMAC-SHA256 blind indexes, Ruby extension, MySQL UDF source, admin SQL contracts, and migration helpers."
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.1"

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "ext/**/*", "mysql_udf/**/*", "sql/**/*", "docs/**/*", "examples/**/*", "README.md", "LICENSE.txt", "Rakefile"]
  end
  spec.extensions = ["ext/secure_db_fields/extconf.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
end
