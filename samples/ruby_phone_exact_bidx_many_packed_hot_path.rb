# frozen_string_literal: true

# Native hot-path sample for packed batch phone exact blind indexes:
#   SecureDBFields::Crypto.phone_blind_index_many_packed(e164_values, key:)

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_phone_exact_bidx_many_packed_hot_path"
key = SDFSample::DEFAULT_BIDX_KEY
batch_size = Integer(ENV.fetch("BATCH_SIZE", "256"))
phones = Array.new(batch_size) do |i|
  "+7777#{format('%07d', i % 10_000_000)}".b.freeze
end.freeze
preheat_iterations = SDFSample.preheat_iterations(20)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_phone_bidx_many_packed|sdf_is_canonical_e164|rb_sdf_hmac_sha256|SHA256_|OPENSSL|CRYPTO"

preheat_iterations.times do
  out = SecureDBFields::Crypto.phone_blind_index_many_packed(phones, key: key)
  SDFSample.assert_binary_size!(out, batch_size * 32, "preheat_packed")
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.phone_blind_index_many_packed(phones, key: key)",
  native_grep: native_grep,
  extra: {
    batch_size: batch_size,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.phone_blind_index_many_packed -> SecureDBFields::Native.phone_blind_index_many_packed",
    "rb_sdf_phone_bidx_many_packed",
    "sdf_is_canonical_e164 validation",
    "custom fixed HMAC-SHA256 with packed output"
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
  last = SecureDBFields::Crypto.phone_blind_index_many_packed(phones, key: key)
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
puts "last_result_bytes=#{last.bytesize if last.respond_to?(:bytesize)}"
puts "gc_delta=#{SDFSample.gc_delta(before_gc, after_gc)}"
puts "last_first_bidx_hex=#{SDFSample.hex(last.byteslice(0, 32))}" if last
