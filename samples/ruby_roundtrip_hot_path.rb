# frozen_string_literal: true

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_roundtrip_hot_path"
key = SDFSample::DEFAULT_ENC_KEY
key_id = Integer(ENV.fetch("KEY_ID", "1"))
value = ENV.fetch("VALUE", SDFSample::DEFAULT_PHONE).b.freeze
aad = SDFSample.aad.freeze
preheat_iterations = SDFSample.preheat_iterations(10)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_encrypt|rb_sdf_decrypt|sdf_encrypt_aes_256_gcm|sdf_decrypt_aes_256_gcm|sdf_is_valid_envelope|RAND_bytes|EVP_|AES|GCM|CRYPTO|OPENSSL|malloc|free|sdf_secure_clear"

preheat_iterations.times do
  enc = SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: key_id)
  out = SecureDBFields::Crypto.decrypt(enc, key: key, aad: aad)
  raise "preheat mismatch" unless out == value
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "encrypt(value) then decrypt(envelope)",
  native_grep: native_grep,
  extra: {
    value_bytes: value.bytesize,
    aad_bytes: aad.bytesize,
    key_id: key_id,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "rb_sdf_encrypt + rb_sdf_decrypt",
    "sdf_encrypt_aes_256_gcm + sdf_decrypt_aes_256_gcm",
    "RAND_bytes nonce generation",
    "EVP AES-256-GCM encrypt/decrypt paths",
    "Ruby String allocation + native malloc/free overhead"
  ]
)

last = SDFSample.run_hot_loop do
  enc = SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: key_id)
  SecureDBFields::Crypto.decrypt(enc, key: key, aad: aad)
end

raise "last mismatch" unless last == value
puts "last_plaintext=#{last.inspect}"
