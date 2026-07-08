# frozen_string_literal: true

# Native hot-path sample for generic blind indexes:
#   SecureDBFields::Crypto.blind_index(value, key:)
#
# Run:
#   bundle exec ruby samples/ruby_blind_index_hot_path.rb

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_blind_index_hot_path"
key = SDFSample::DEFAULT_BIDX_KEY
value = ENV.fetch("VALUE", SDFSample::DEFAULT_EMAIL).b.freeze
preheat_iterations = SDFSample.preheat_iterations(100)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_blind_index|sdf_blind_index|sdf_validate_key|HMAC|SHA256|EVP_sha256|OPENSSL|CRYPTO"

preheat_iterations.times do
  out = SecureDBFields::Crypto.blind_index(value, key: key)
  SDFSample.assert_binary_size!(out, 32, "preheat")
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.blind_index(value, key: key)",
  native_grep: native_grep,
  extra: {
    value_bytes: value.bytesize,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.blind_index -> SecureDBFields::Native.blind_index",
    "rb_sdf_blind_index",
    "sdf_blind_index",
    "OpenSSL HMAC(...EVP_sha256...)"
  ]
)

last = SDFSample.run_hot_loop do
  SecureDBFields::Crypto.blind_index(value, key: key)
end

SDFSample.assert_binary_size!(last, 32, "last_hot_loop") if last
puts "last_bidx_hex=#{SDFSample.hex(last)}" if last
