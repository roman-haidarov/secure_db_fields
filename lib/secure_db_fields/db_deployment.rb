# frozen_string_literal: true

require "digest"
require "fileutils"
require "optparse"
require "rubygems/package"
require "securerandom"
require "stringio"
require "tmpdir"
require "zlib"
require_relative "version"

module SecureDBFields
  module DBDeployment
    ROOT = File.expand_path("../..", __dir__)
    BUNDLE_FORMAT_VERSION = 1
    MYSQL_TARGET = "mysql"

    class Error < StandardError; end

    class CLI
      def self.run(argv)
        new.run(argv)
      end

      def run(argv)
        command = argv.shift
        case command
        when "package"
          PackageCommand.new.run(argv)
        when "view"
          ViewCommand.new.run(argv)
        when "help", "--help", "-h", nil
          puts help
          0
        else
          raise OptionParser::InvalidOption, "unknown db command: #{command.inspect}"
        end
      rescue OptionParser::ParseError, Error => e
        warn "secure_db_fields db: #{e.message}"
        2
      rescue SystemCallError, IOError => e
        warn "secure_db_fields db: #{e.message}"
        1
      end

      private

      def help
        <<~TEXT
          Usage:
            secure_db_fields db package mysql [--output PATH] [--force]

            secure_db_fields db view mysql --table DB.TABLE --field NAME:ENC_COLUMN \\
              --uid-column secure_row_uid --view DB.VIEW --columns ID,CREATED_AT \\
              [--as NAME] [--output PATH]

          `package` creates a self-contained source bundle for the DBA. The DBA
          extracts it on the database host and runs `make doctor`, `sudo make
          install`, `make enable`, then `make status`.

          `view` emits an admin readable view. It is for projection/display only;
          indexed search must use physical bidx columns and helper procedures or
          query templates.
        TEXT
      end
    end

    class PackageCommand
      def run(argv)
        target = argv.shift
        raise OptionParser::MissingArgument, "TARGET must be mysql" if target.nil?
        raise OptionParser::InvalidArgument, "TARGET must be mysql" unless target == MYSQL_TARGET

        options = { output: nil, force: false }
        parser = OptionParser.new do |opts|
          opts.banner = "Usage: secure_db_fields db package mysql [OPTIONS]"
          opts.on("-o", "--output PATH", "write the deployment archive to PATH") { |value| options[:output] = value }
          opts.on("-f", "--force", "overwrite an existing archive") { options[:force] = true }
          opts.on("-h", "--help", "show this help") { puts opts; return 0 }
        end
        parser.parse!(argv)
        raise OptionParser::InvalidOption, argv.join(" ") unless argv.empty?

        output = options[:output] || "secure_db_fields-mysql-#{SecureDBFields::VERSION}.tar.gz"
        DeploymentBundle.new(output, force: options[:force]).write!
        puts File.expand_path(output)
        0
      end
    end

    class ViewCommand
      IDENTIFIER = /\A[A-Za-z_][A-Za-z0-9_]*\z/.freeze
      QUALIFIED_IDENTIFIER = /\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?\z/.freeze

      def run(argv)
        target = argv.shift
        raise OptionParser::MissingArgument, "TARGET must be mysql" if target.nil?
        raise OptionParser::InvalidArgument, "TARGET must be mysql" unless target == MYSQL_TARGET

        options = { columns: [], output: nil, as: nil, uid_column: "secure_row_uid" }
        parser = OptionParser.new do |opts|
          opts.banner = "Usage: secure_db_fields db view mysql --table DB.TABLE --field NAME:ENC_COLUMN --view DB.VIEW [OPTIONS]"
          opts.on("--table NAME", "source table, optionally database-qualified") { |value| options[:table] = value }
          opts.on("--field SPEC", "plaintext:encrypted_column, e.g. phone:phone_enc") { |value| options[:field] = value }
          opts.on("--uid-column NAME", "row UID column for AAD (default: secure_row_uid)") { |value| options[:uid_column] = value }
          opts.on("--view NAME", "destination view, optionally database-qualified") { |value| options[:view] = value }
          opts.on("--columns LIST", "comma-separated plain columns to expose") { |value| options[:columns] = value.split(",").map(&:strip).reject(&:empty?) }
          opts.on("--as NAME", "decrypted column alias (default: plaintext field name)") { |value| options[:as] = value }
          opts.on("-o", "--output PATH", "write SQL to PATH instead of stdout") { |value| options[:output] = value }
          opts.on("-h", "--help", "show this help") { puts opts; return 0 }
        end
        parser.parse!(argv)
        raise OptionParser::InvalidOption, argv.join(" ") unless argv.empty?

        sql = ReadableView.new(options).to_sql
        if options[:output]
          write_text_atomically(options[:output], sql)
          puts File.expand_path(options[:output])
        else
          $stdout.write(sql)
        end
        0
      end

      private

      def write_text_atomically(path, contents)
        directory = File.dirname(File.expand_path(path))
        FileUtils.mkdir_p(directory)
        temporary = File.join(directory, ".secure-db-fields-view-#{Process.pid}-#{SecureRandom.hex(8)}")
        File.open(temporary, "wb", 0o644) { |file| file.write(contents) }
        File.rename(temporary, path)
      ensure
        File.delete(temporary) if defined?(temporary) && File.exist?(temporary)
      end
    end

    class ReadableView
      IDENTIFIER = ViewCommand::IDENTIFIER
      QUALIFIED_IDENTIFIER = ViewCommand::QUALIFIED_IDENTIFIER

      def initialize(options)
        @table = qualified_identifier!(options.fetch(:table), "--table")
        @view = qualified_identifier!(options.fetch(:view), "--view")
        @uid_column = identifier!(options.fetch(:uid_column), "--uid-column")
        field = options.fetch(:field)
        @plain_field, @encrypted_column = parse_field(field)
        @alias = identifier!(options[:as] || @plain_field, "--as")
        @columns = Array(options.fetch(:columns)).map { |column| identifier!(column, "--columns") }
        @aad_table = @table.split(".").last
      rescue KeyError => e
        raise OptionParser::MissingArgument, e.key.to_s
      end

      def to_sql
        select_list = (@columns.map { |column| "  `#{column}`" } + [decrypt_expression]).join(",\n")
        <<~SQL
          -- Generated by secure_db_fields #{SecureDBFields::VERSION}.
          -- This view is for display/projection. Do not use WHERE on decrypted columns for indexed search.
          CREATE OR REPLACE ALGORITHM=MERGE VIEW #{quote_qualified(@view)} AS
          SELECT
          #{select_list}
          FROM #{quote_qualified(@table)};
        SQL
      end

      private

      def decrypt_expression
        "  secure_db_fields_decrypt_field(`#{@encrypted_column}`, '#{sql_literal(@aad_table)}', '#{sql_literal(@plain_field)}', `#{@uid_column}`) AS `#{@alias}`"
      end

      def parse_field(field)
        unless field && field.include?(":")
          raise OptionParser::MissingArgument, "--field plaintext:encrypted_column"
        end
        plain, encrypted = field.split(":", 2)
        [identifier!(plain, "--field plaintext"), identifier!(encrypted, "--field encrypted_column")]
      end

      def identifier!(value, flag)
        text = value.to_s
        raise OptionParser::InvalidArgument, "#{flag} must be a SQL identifier" unless IDENTIFIER.match?(text)
        text
      end

      def qualified_identifier!(value, flag)
        text = value.to_s
        raise OptionParser::InvalidArgument, "#{flag} must be a SQL identifier or DB.TABLE" unless QUALIFIED_IDENTIFIER.match?(text)
        text
      end

      def quote_qualified(name)
        name.split(".").map { |part| "`#{part}`" }.join(".")
      end

      def sql_literal(value)
        value.gsub("'", "''")
      end
    end

    class DeploymentBundle
      BUNDLE_FILES = [
        ["db_deployment/mysql/Makefile", "Makefile"],
        ["db_deployment/mysql/README.md", "README.md"],
        ["db_deployment/mysql/bin/common", "bin/common", 0o755],
        ["db_deployment/mysql/bin/doctor", "bin/doctor", 0o755],
        ["db_deployment/mysql/bin/install", "bin/install", 0o755],
        ["db_deployment/mysql/bin/enable", "bin/enable", 0o755],
        ["db_deployment/mysql/bin/disable", "bin/disable", 0o755],
        ["db_deployment/mysql/bin/status", "bin/status", 0o755],
        ["db_deployment/mysql/bin/verify", "bin/verify", 0o755],
        ["db_deployment/mysql/bin/uninstall", "bin/uninstall", 0o755],
        ["db_deployment/mysql/sql/install.sql", "sql/install.sql"],
        ["db_deployment/mysql/sql/uninstall.sql", "sql/uninstall.sql"],
        ["db_deployment/mysql/sql/examples.sql", "sql/examples.sql"],
        ["mysql_udf/src/secure_db_fields_mysql.c", "src/secure_db_fields_mysql.c"],
        ["mysql_udf/src/mysql_udf_abi_57.h", "src/mysql_udf_abi_57.h"],
        ["ext/secure_db_fields/secure_db_fields_core.c", "src/secure_db_fields_core.c"],
        ["ext/secure_db_fields/secure_db_fields_core.h", "src/secure_db_fields_core.h"]
      ].freeze

      attr_reader :output

      def initialize(output, force: false)
        @output = output
        @force = force
      end

      def write!
        path = File.expand_path(output)
        raise Error, "#{path} already exists (use --force)" if File.exist?(path) && !@force

        FileUtils.mkdir_p(File.dirname(path))
        tmp = File.join(File.dirname(path), ".secure-db-fields-db-bundle-#{Process.pid}-#{SecureRandom.hex(8)}.tar.gz")
        Zlib::GzipWriter.open(tmp) do |gz|
          Gem::Package::TarWriter.new(gz) do |tar|
            BUNDLE_FILES.each do |src, dst, mode|
              add_file(tar, src, dst, mode || 0o644)
            end
            add_text(tar, "VERSION", SecureDBFields::VERSION + "\n")
            add_text(tar, "BUNDLE_FORMAT", BUNDLE_FORMAT_VERSION.to_s + "\n")
            add_text(tar, "SHA256SUMS", checksums)
          end
        end
        File.rename(tmp, path)
      ensure
        File.delete(tmp) if defined?(tmp) && File.exist?(tmp)
      end

      def bundle_name
        "secure_db_fields-mysql-#{SecureDBFields::VERSION}"
      end

      private

      def add_file(tar, src, dst, mode)
        full = File.join(ROOT, src)
        raise Error, "missing bundle source: #{src}" unless File.file?(full)
        data = File.binread(full)
        add_bytes(tar, File.join(bundle_name, dst), data, mode)
      end

      def add_text(tar, dst, data)
        add_bytes(tar, File.join(bundle_name, dst), data, 0o644)
      end

      def add_bytes(tar, name, data, mode)
        entry = StringIO.new(data)
        tar.add_file_simple(name, mode, data.bytesize) { |io| IO.copy_stream(entry, io) }
      end

      def checksums
        lines = BUNDLE_FILES.map do |src, dst, _mode|
          data = File.binread(File.join(ROOT, src))
          "#{Digest::SHA256.hexdigest(data)}  #{dst}"
        end
        lines.join("\n") + "\n"
      end
    end
  end
end
