# frozen_string_literal: true

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_encrypt_hot_path"
key = SDFSample::DEFAULT_ENC_KEY
key_id = Integer(ENV.fetch("KEY_ID", "1"))
value = ENV.fetch("VALUE", SDFSample::DEFAULT_PHONE).b.freeze
aad = SDFSample.aad.freeze
preheat_iterations = SDFSample.preheat_iterations(10)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_encrypt|sdf_encrypt_aes_256_gcm|sdf_validate_key|sdf_u32be_write|RAND_bytes|EVP_|AES|GCM|CRYPTO|OPENSSL|malloc|free"

preheat_iterations.times do
  out = SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: key_id)
  SDFSample.assert_envelope!(out, "preheat")
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: #{key_id})",
  native_grep: native_grep,
  extra: {
    value_bytes: value.bytesize,
    aad_bytes: aad.bytesize,
    key_id: key_id,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.encrypt -> SecureDBFields::Native.encrypt",
    "rb_sdf_encrypt",
    "sdf_encrypt_aes_256_gcm",
    "RAND_bytes for 96-bit GCM nonce",
    "EVP_aes_256_gcm / EVP_EncryptInit_ex / EVP_EncryptUpdate / EVP_EncryptFinal_ex",
    "EVP_CIPHER_CTX_ctrl(...GET_TAG...)",
    "MCEN envelope header build via sdf_u32be_write"
  ]
)

last = SDFSample.run_hot_loop do
  SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: key_id)
end

SDFSample.assert_envelope!(last, "last_hot_loop") if last
puts "last_key_id=#{SecureDBFields::Crypto.key_id(last)}" if last
