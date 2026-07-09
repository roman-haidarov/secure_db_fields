# frozen_string_literal: true

module SecureDBFields
  class Keyring
    DEFAULT_PATH = "/etc/secure_db_fields/keys.env"
    APP_RELATIVE_PATH = "config/secure_db_fields/keys.env"

    attr_reader :path

    def self.default_path
      env = ENV["SECURE_DB_FIELDS_KEY_FILE"]
      return env if env && !env.empty?

      if defined?(Rails) && Rails.respond_to?(:root) && Rails.root
        rails_path = Rails.root.join(APP_RELATIVE_PATH).to_s
        return rails_path if File.exist?(rails_path)
      end

      app_path = File.expand_path(APP_RELATIVE_PATH, Dir.pwd)
      return app_path if File.exist?(app_path)

      DEFAULT_PATH
    end

    def initialize(path = self.class.default_path)
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
      @values[name]
    end

    def parse_file(path)
      validate_file_permissions!(path)
      values = {}
      File.readlines(path, chomp: true).each do |line|
        stripped = line.strip
        next if stripped.empty? || stripped.start_with?("#")
        key, value = stripped.split("=", 2)
        next unless key && value
        name = key.strip
        text = value.strip
        values[name] = name.end_with?("_HEX") ? Crypto.hex_decode_key(text) : text
      end
      values.freeze
    rescue Errno::ENOENT
      raise KeyError, "key file not found: #{path}"
    end

    def validate_file_permissions!(path)
      info = File.lstat(path)
      raise KeyError, "key file must not be a symlink: #{path}" if info.symlink?
      stat = File.stat(path)
      raise KeyError, "key file must be a regular file: #{path}" unless stat.file?
      raise KeyError, "key file permissions are too open: #{path}" unless (stat.mode & 0o027).zero?
    end
  end
end
