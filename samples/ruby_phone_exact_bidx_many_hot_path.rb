# frozen_string_literal: true

# Native hot-path sample for batch phone exact blind indexes:
#   SecureDBFields::Crypto.phone_blind_index_many(e164_values, key:)
#
# Run:
#   bundle exec ruby samples/ruby_phone_exact_bidx_many_hot_path.rb

require_relative "_sample_helper"

sample_name = "secure_db_fields_ruby_phone_exact_bidx_many_hot_path"
key = SDFSample::DEFAULT_BIDX_KEY
batch_size = Integer(ENV.fetch("BATCH_SIZE", "256"))
phones = Array.new(batch_size) { |i| "+7777%07d" % i }.map { |v| v.b.freeze }.freeze
preheat_iterations = SDFSample.preheat_iterations(20)
native_grep = "SecureDBFields|secure_db_fields|rb_sdf_phone_bidx_many|sdf_is_canonical_e164|rb_sdf_hmac_sha256|SHA256_|OPENSSL|CRYPTO"

preheat_iterations.times do
  out = SecureDBFields::Crypto.phone_blind_index_many(phones, key: key)
  raise "bad preheat size" unless out.size == batch_size
  SDFSample.assert_binary_size!(out.first, 32, "preheat_first")
end

SDFSample.print_banner(
  sample_name: sample_name,
  call: "SecureDBFields::Crypto.phone_blind_index_many(phones, key: key)",
  native_grep: native_grep,
  extra: {
    batch_size: batch_size,
    preheat_iterations: preheat_iterations
  },
  expected: [
    "SecureDBFields::Crypto.phone_blind_index_many -> SecureDBFields::Native.phone_blind_index_many",
    "rb_sdf_phone_bidx_many",
    "sdf_is_canonical_e164",
    "custom fixed HMAC-SHA256 with precomputed ipad/opad"
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
  last = SecureDBFields::Crypto.phone_blind_index_many(phones, key: key)
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
puts "last_first_bidx_hex=#{SDFSample.hex(last.first)}" if last
