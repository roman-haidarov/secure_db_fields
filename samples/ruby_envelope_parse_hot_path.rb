# frozen_string_literal: true

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_envelope_parse_hot_path"
key = SDFSample::DEFAULT_ENC_KEY
key_id = Integer(ENV.fetch("KEY_ID", "123"))
value = ENV.fetch("VALUE", SDFSample::DEFAULT_PHONE).b.freeze
aad = SDFSample.aad.freeze
envelope = SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: key_id).freeze
preheat_iterations = SDFSample.preheat_iterations(500)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_valid_envelope|rb_sdf_key_id|sdf_is_valid_envelope|sdf_parse_key_id|sdf_u32be_read|memcmp|MCEN"

preheat_iterations.times do
  raise "invalid envelope" unless SecureDBFields::Crypto.valid_envelope?(envelope)
  raise "wrong key_id" unless SecureDBFields::Crypto.key_id(envelope) == key_id
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.valid_envelope?(envelope); SecureDBFields::Crypto.key_id(envelope)",
  native_grep: native_grep,
  extra: {
    envelope_bytes: envelope.bytesize,
    key_id: key_id,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.valid_envelope? -> rb_sdf_valid_envelope",
    "SecureDBFields::Crypto.key_id -> rb_sdf_key_id",
    "sdf_is_valid_envelope",
    "sdf_parse_key_id / sdf_u32be_read",
    "no OpenSSL EVP/HMAC hot path expected here"
  ]
)

last = SDFSample.run_hot_loop do
  ok = SecureDBFields::Crypto.valid_envelope?(envelope)
  id = SecureDBFields::Crypto.key_id(envelope)
  ok && id
end

raise "last parse mismatch" unless last == key_id
puts "last_key_id=#{last}"
