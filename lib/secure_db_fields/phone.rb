# frozen_string_literal: true

module SecureDBFields
  module Phone
    module_function

    def canonical_e164?(value)
      Native.e164?(value.to_s)
    end

    def assert_canonical_e164!(value)
      str = value.to_s
      raise ArgumentError, "phone must be canonical E.164, e.g. +77771234567" unless canonical_e164?(str)
      str
    end
  end
end
