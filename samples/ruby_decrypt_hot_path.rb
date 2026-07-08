# frozen_string_literal: true

# Native hot-path sample for:
#   SecureDBFields::Crypto.decrypt(envelope, key:, aad:)
#
# Run:
#   bundle exec ruby samples/ruby_decrypt_hot_path.rb

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_decrypt_hot_path"
key = SDFSample::DEFAULT_ENC_KEY
key_id = Integer(ENV.fetch("KEY_ID", "1"))
value = ENV.fetch("VALUE", SDFSample::DEFAULT_PHONE).b.freeze
aad = SDFSample.aad.freeze
envelope = SecureDBFields::Crypto.encrypt(value, key: key, aad: aad, key_id: key_id).freeze
preheat_iterations = SDFSample.preheat_iterations(25)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_decrypt|sdf_decrypt_aes_256_gcm|sdf_is_valid_envelope|sdf_u32be_read|EVP_|AES|GCM|CRYPTO|OPENSSL|authentication|malloc|free|sdf_secure_clear"

preheat_iterations.times do
  out = SecureDBFields::Crypto.decrypt(envelope, key: key, aad: aad)
  raise "preheat mismatch" unless out == value
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.decrypt(envelope, key: key, aad: aad)",
  native_grep: native_grep,
  extra: {
    plaintext_bytes: value.bytesize,
    envelope_bytes: envelope.bytesize,
    aad_bytes: aad.bytesize,
    key_id: SecureDBFields::Crypto.key_id(envelope),
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.decrypt -> SecureDBFields::Native.decrypt",
    "rb_sdf_decrypt",
    "sdf_decrypt_aes_256_gcm",
    "sdf_is_valid_envelope / sdf_u32be_read",
    "EVP_aes_256_gcm / EVP_DecryptInit_ex / EVP_DecryptUpdate",
    "EVP_CIPHER_CTX_ctrl(...SET_TAG...) / EVP_DecryptFinal_ex authentication check",
    "sdf_secure_clear on plaintext scratch buffers"
  ]
)

last = SDFSample.run_hot_loop do
  SecureDBFields::Crypto.decrypt(envelope, key: key, aad: aad)
end

raise "last mismatch" unless last == value
puts "last_plaintext=#{last.inspect}"
