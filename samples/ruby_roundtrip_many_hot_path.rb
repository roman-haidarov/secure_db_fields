# frozen_string_literal: true

# Native hot-path sample for batch encrypt + decrypt roundtrip.

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_roundtrip_many_hot_path"
key = SDFSample::DEFAULT_ENC_KEY
key_id = Integer(ENV.fetch("KEY_ID", "1"))
batch_size = Integer(ENV.fetch("BATCH_SIZE", "256"))
values = Array.new(batch_size) { |i| "+7777#{format('%07d', i % 10_000_000)}".b.freeze }.freeze
aads = Array.new(batch_size) do |i|
  uid = [i].pack("Q<") + [i ^ 0x5a5a5a5a].pack("Q<")
  SDFSample.aad("clients", "phone", uid).freeze
end.freeze
preheat_iterations = SDFSample.preheat_iterations(10)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_encrypt_many|rb_sdf_decrypt_many|sdf_encrypt_aes_256_gcm_into|sdf_decrypt_aes_256_gcm_into|RAND_bytes|EVP_|AES|GCM|CRYPTO|OPENSSL"

preheat_iterations.times do
  encrypted = SecureDBFields::Crypto.encrypt_many(values, key: key, aads: aads, key_id: key_id)
  plain = SecureDBFields::Crypto.decrypt_many(encrypted, key: key, aads: aads)
  raise "preheat mismatch" unless plain == values
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "encrypt_many + decrypt_many",
  native_grep: native_grep,
  extra: {
    batch_size: batch_size,
    value_bytes: values.first.bytesize,
    aad_bytes: aads.first.bytesize,
    key_id: key_id,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.encrypt_many / decrypt_many",
    "direct output into Ruby String for each envelope/plaintext",
    "one Ruby->C call per batch step"
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
  encrypted = SecureDBFields::Crypto.encrypt_many(values, key: key, aads: aads, key_id: key_id)
  last = SecureDBFields::Crypto.decrypt_many(encrypted, key: key, aads: aads)
  batches += 1
  ops += batch_size
end
elapsed = SDFSample.monotonic - started
after_gc = SDFSample.gc_snapshot
GC.enable

raise "last mismatch" unless last == values
puts "batches=#{batches}"
puts "count=#{ops}"
puts "elapsed=#{format('%.6f', elapsed)}"
puts "ops_per_sec=#{format('%.6f', ops / elapsed)}"
puts "batches_per_sec=#{format('%.6f', batches / elapsed)}"
puts "sec_per_op=#{format('%.9f', elapsed / [ops, 1].max)}"
puts "last_result_class=#{last.class if last}"
puts "last_result_count=#{last.size if last.respond_to?(:size)}"
puts "gc_delta=#{SDFSample.gc_delta(before_gc, after_gc)}"
