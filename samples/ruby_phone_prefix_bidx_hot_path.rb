# frozen_string_literal: true

# Native hot-path sample for canonical E.164 prefix phone search tokens:
#   SecureDBFields::Crypto.phone_prefix_blind_index(e164, prefix_digits:, key:)
#
# Run:
#   PREFIX_DIGITS=7 bundle exec ruby samples/ruby_phone_prefix_bidx_hot_path.rb

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_phone_prefix_bidx_hot_path"
key = SDFSample::DEFAULT_BIDX_KEY
phone = ENV.fetch("PHONE", SDFSample::DEFAULT_PHONE).b.freeze
prefix_digits = Integer(ENV.fetch("PREFIX_DIGITS", "7"))
preheat_iterations = SDFSample.preheat_iterations(100)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_phone_prefix_bidx|sdf_phone_prefix_bidx|sdf_is_canonical_e164|sdf_blind_index|HMAC|SHA256|EVP_sha256|OPENSSL|CRYPTO"

raise "PHONE must be canonical E.164" unless SecureDBFields::Phone.canonical_e164?(phone)

preheat_iterations.times do
  out = SecureDBFields::Crypto.phone_prefix_blind_index(phone, prefix_digits: prefix_digits, key: key)
  SDFSample.assert_binary_size!(out, 32, "preheat")
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.phone_prefix_blind_index(phone, prefix_digits: #{prefix_digits}, key: key)",
  native_grep: native_grep,
  extra: {
    phone: phone,
    prefix_digits: prefix_digits,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.phone_prefix_blind_index -> Native.phone_prefix_blind_index",
    "rb_sdf_phone_prefix_bidx",
    "sdf_phone_prefix_bidx",
    "sdf_is_canonical_e164 strict validator",
    "prefix slice in C, then sdf_blind_index -> OpenSSL HMAC-SHA256"
  ]
)

last = SDFSample.run_hot_loop do
  SecureDBFields::Crypto.phone_prefix_blind_index(phone, prefix_digits: prefix_digits, key: key)
end

SDFSample.assert_binary_size!(last, 32, "last_hot_loop") if last
puts "last_bidx_hex=#{SDFSample.hex(last)}" if last
