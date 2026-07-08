# frozen_string_literal: true

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_encrypt_many_hot_path"
key = SDFSample::DEFAULT_ENC_KEY
key_id = Integer(ENV.fetch("KEY_ID", "1"))
batch_size = Integer(ENV.fetch("BATCH_SIZE", "256"))
values = Array.new(batch_size) { |i| "+7777#{format('%07d', i % 10_000_000)}".b.freeze }.freeze
aads = Array.new(batch_size) do |i|
  uid = [i].pack("Q<") + [i ^ 0x5a5a5a5a].pack("Q<")
  SDFSample.aad("clients", "phone", uid).freeze
end.freeze
preheat_iterations = SDFSample.preheat_iterations(10)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_encrypt_many|sdf_encrypt_aes_256_gcm_into|RAND_bytes|EVP_|AES|GCM|CRYPTO|OPENSSL|malloc|free"

preheat_iterations.times do
  out = SecureDBFields::Crypto.encrypt_many(values, key: key, aads: aads, key_id: key_id)
  raise "bad preheat count" unless out.size == batch_size
  SDFSample.assert_envelope!(out.first, "preheat_first")
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.encrypt_many(values, key: key, aads: aads, key_id: #{key_id})",
  native_grep: native_grep,
  extra: {
    batch_size: batch_size,
    value_bytes: values.first.bytesize,
    aad_bytes: aads.first.bytesize,
    key_id: key_id,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.encrypt_many -> SecureDBFields::Native.encrypt_many",
    "rb_sdf_encrypt_many",
    "sdf_encrypt_aes_256_gcm_into writes directly into Ruby String",
    "RAND_bytes per envelope",
    "EVP_aes_256_gcm / EVP_Encrypt*"
  ]
)

GC.start
GC.disable
before_gc = SDFSample.gc_snapshot
sleep SDFSample.sleep_before_hot_loop

batches = 0
ops = 0
started = SDFSample.monotonic
deadline = started + SDFSample.duration
last = nil
while SDFSample.monotonic < deadline
  last = SecureDBFields::Crypto.encrypt_many(values, key: key, aads: aads, key_id: key_id)
  batches += 1
  ops += batch_size
end
elapsed = SDFSample.monotonic - started
after_gc = SDFSample.gc_snapshot
GC.enable

puts "batches=#{batches}"
puts "count=#{ops}"
puts "elapsed=#{format('%.6f', elapsed)}"
puts "ops_per_sec=#{format('%.6f', ops / elapsed)}"
puts "batches_per_sec=#{format('%.6f', batches / elapsed)}"
puts "sec_per_op=#{format('%.9f', elapsed / [ops, 1].max)}"
puts "last_result_class=#{last.class if last}"
puts "last_result_count=#{last.size if last.respond_to?(:size)}"
puts "last_result_first_bytes=#{last.first.bytesize if last && last.first.respond_to?(:bytesize)}"
puts "gc_delta=#{SDFSample.gc_delta(before_gc, after_gc)}"
puts "last_first_key_id=#{SecureDBFields::Crypto.key_id(last.first)}" if last
