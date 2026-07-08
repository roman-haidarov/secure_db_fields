# frozen_string_literal: true

# Shared helpers for SecureDBFields native hot-path samples.
# These files are intentionally dependency-light and Ruby 2.7.1 compatible.

$stdout.sync = true
$stderr.sync = true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

begin
  require "secure_db_fields"
rescue LoadError => e
  warn "failed to require secure_db_fields: #{e.message}"
  warn "run from project root after compiling the extension, for example:"
  warn "  bundle install"
  warn "  bundle exec rake compile"
  warn "  bundle exec ruby samples/<sample>.rb"
  raise
end

module SDFSample
  module_function

  DEFAULT_ENC_KEY = "a".b * 32
  DEFAULT_BIDX_KEY = "b".b * 32
  DEFAULT_ROW_UID = (0...16).map { |i| i.chr }.join.b.freeze
  DEFAULT_PHONE = "+77771234567".b.freeze
  DEFAULT_EMAIL = "client@example.com".b.freeze

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def duration
    Float(ENV.fetch("DURATION", "25.0"))
  end

  def sleep_before_hot_loop
    Float(ENV.fetch("SLEEP_BEFORE_HOT_LOOP", "7.0"))
  end

  def preheat_iterations(default)
    Integer(ENV.fetch("PREHEAT_ITERATIONS", default.to_s))
  end

  def gc_snapshot
    stat = GC.stat
    {
      total_allocated_objects: stat.fetch(:total_allocated_objects),
      minor_gc_count: stat.fetch(:minor_gc_count),
      major_gc_count: stat.fetch(:major_gc_count)
    }
  end

  def gc_delta(before, after)
    before.each_with_object({}) do |(key, value), out|
      out[key] = after.fetch(key) - value
    end
  end

  def hex(bytes)
    bytes.unpack1("H*")
  end

  def assert_binary_size!(value, bytesize, label)
    raise "#{label}: expected String, got #{value.class}" unless value.is_a?(String)
    raise "#{label}: expected #{bytesize} bytes, got #{value.bytesize}" unless value.bytesize == bytesize
    value
  end

  def assert_envelope!(value, label)
    raise "#{label}: expected String, got #{value.class}" unless value.is_a?(String)
    raise "#{label}: too small: #{value.bytesize}" if value.bytesize < 38
    raise "#{label}: invalid MCEN envelope" unless SecureDBFields::Crypto.valid_envelope?(value)
    value
  end

  def aad(table = "clients", column = "phone", row_uid = DEFAULT_ROW_UID)
    SecureDBFields::Crypto.aad(table, column, row_uid)
  end

  def print_banner(sample_name:, call:, native_grep:, expected:, extra: {})
    sleep_s = sleep_before_hot_loop
    duration_s = duration
    sample_seconds = (sleep_s + duration_s + 15).ceil
    sample_file = "/tmp/#{sample_name}.sample"
    txt_file = File.expand_path("results/#{sample_name}.txt", __dir__)
    txt_dir = File.dirname(txt_file)

    puts "pid=#{Process.pid}"
    puts "ruby=#{RUBY_DESCRIPTION}"
    puts "platform=#{RUBY_PLATFORM}"
    puts "mode=#{sample_name}"
    puts "call=#{call}"
    extra.each { |key, value| puts "#{key}=#{value}" }
    puts "duration=#{duration_s}"
    puts "sleep_before_hot_loop=#{sleep_s}"
    puts "sample_seconds=#{sample_seconds}"
    puts "sample_file=#{sample_file}"
    puts "txt_file=#{txt_file}"
    puts
    puts "Copy this one-line macOS capture command in another console:"
    puts %(mkdir -p "#{txt_dir}"; OUT="#{txt_file}"; SAMPLE="#{sample_file}"; { sample #{Process.pid} #{sample_seconds} -f "$SAMPLE"; echo; echo "===== focused SecureDBFields/native symbols ====="; filtercalltree "$SAMPLE" | grep -E "#{native_grep}" | head -300; echo; echo "===== filtercalltree head -300 ====="; filtercalltree "$SAMPLE" | head -300; } 2>&1 | tee "$OUT")
    puts
    puts "Optional Linux perf command if you run this on Linux with perf available:"
    puts %(perf record -F 997 -g -p #{Process.pid} -- sleep #{sample_seconds}; perf report --stdio | head -240)
    puts
    puts "Expected hot native symbols:"
    expected.each { |line| puts "  #{line}" }
    puts
    puts "sleep=#{sleep_s} seconds before hot loop"
    puts
  end

  def run_hot_loop
    GC.start
    GC.disable
    before_gc = gc_snapshot
    sleep sleep_before_hot_loop

    count = 0
    started = monotonic
    deadline = started + duration
    last_result = nil

    while monotonic < deadline
      last_result = yield
      count += 1
    end

    elapsed = monotonic - started
    after_gc = gc_snapshot

    puts "count=#{count}"
    puts "elapsed=#{format('%.6f', elapsed)}"
    puts "ops_per_sec=#{format('%.6f', count / elapsed)}"
    puts "sec_per_op=#{format('%.9f', elapsed / [count, 1].max)}"
    puts "last_result_class=#{last_result.class if last_result}"
    puts "last_result_bytes=#{last_result.bytesize if last_result.respond_to?(:bytesize)}"
    puts "gc_delta=#{gc_delta(before_gc, after_gc)}"
    last_result
  ensure
    GC.enable
  end
end
