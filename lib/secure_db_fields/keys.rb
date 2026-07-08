# frozen_string_literal: true

module SecureDBFields
  class Keyring
    DEFAULT_PATH = "/etc/secure_db_fields/keys.env"

    attr_reader :path

    def initialize(path = ENV.fetch("SECURE_DB_FIELDS_KEY_FILE", DEFAULT_PATH))
      @path = path
      @values = parse_file(path)
    end

    def encryption_key(key_id = 1)
      fetch_hex_key("SDF_ENC_KEY_#{Integer(key_id)}_HEX") ||
        (Integer(key_id) == 1 ? fetch_hex_key("SDF_ENC_KEY_HEX") : nil) ||
        raise(KeyError, "missing encryption key for key_id=#{key_id}")
    end

    def blind_index_key(domain = nil)
      if domain && !domain.to_s.empty?
        name = "SDF_BIDX_#{normalize_domain(domain)}_KEY_HEX"
        fetch_hex_key(name) || raise(KeyError, "missing blind-index key #{name}")
      else
        fetch_hex_key("SDF_BIDX_KEY_HEX") || raise(KeyError, "missing SDF_BIDX_KEY_HEX")
      end
    end

    def active_key_id
      value = @values["SDF_ACTIVE_KEY_ID"]
      value ? Integer(value) : 1
    end

    private

    def normalize_domain(domain)
      domain.to_s.upcase.gsub(/[^A-Z0-9_]/, "_")
    end

    def fetch_hex_key(name)
      hex = @values[name]
      hex && Crypto.hex_decode_key(hex)
    end

    def parse_file(path)
      values = {}
      File.readlines(path, chomp: true).each do |line|
        stripped = line.strip
        next if stripped.empty? || stripped.start_with?("#")
        key, value = stripped.split("=", 2)
        next unless key && value
        values[key.strip] = value.strip
      end
      values.freeze
    rescue Errno::ENOENT
      raise KeyError, "key file not found: #{path}"
    end
  end
end
