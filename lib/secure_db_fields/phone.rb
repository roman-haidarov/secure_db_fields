# frozen_string_literal: true

module SecureDBFields
  module Phone
    module_function

    # Strict validator for canonical E.164 values. This intentionally does not
    # try to parse local formats. Canonicalization must happen at the application
    # boundary, preferably with Phonelib/libphonenumber metadata.
    def canonical_e164?(value)
      Native.e164?(value.to_s.b)
    end

    def assert_canonical_e164!(value)
      str = value.to_s.b
      raise ArgumentError, "phone must be canonical E.164, e.g. +77771234567" unless canonical_e164?(str)
      str
    end
  end
end
