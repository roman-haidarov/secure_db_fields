# frozen_string_literal: true

module SecureDBFields
  module ActiveRecord
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      def secure_db_field(name, encrypted:, blind_index:, row_uid: :secure_row_uid, normalizer: nil, keyring: SecureDBFields::Keyring.new, table_name_for_aad: nil, key_domain: nil)
        field_name = name.to_s
        if normalizer == :phone || (normalizer.nil? && field_name == "phone")
          normalizer = ->(value) { value.nil? ? nil : SecureDBFields::Phone.assert_canonical_e164!(value) }
          key_domain ||= "PHONE"
        end
        normalizer ||= ->(value) { value.nil? ? nil : value.to_s }
        table_for_aad = table_name_for_aad || table_name
        domain = key_domain || "#{table_for_aad}_#{field_name}"

        define_method(name) do
          envelope = public_send(encrypted)
          return nil if envelope.nil?

          key_id = SecureDBFields::Crypto.key_id(envelope)
          key = keyring.encryption_key(key_id)
          uid = public_send(row_uid)
          SecureDBFields::Crypto.decrypt(envelope, key: key, aad: SecureDBFields::Crypto.aad(table_for_aad, field_name, uid))
        end

        define_method("#{name}=") do |value|
          uid = public_send(row_uid)
          if uid.nil? || uid.to_s.b.bytesize != 16
            raise ArgumentError, "#{row_uid} must be 16 bytes before encrypting #{field_name}"
          end

          if value.nil?
            public_send("#{encrypted}=", nil)
            public_send("#{blind_index}=", nil)
            next nil
          end

          normalized = normalizer.call(value)
          key_id = keyring.active_key_id
          enc_key = keyring.encryption_key(key_id)
          bidx_key = keyring.blind_index_key(domain)
          public_send("#{encrypted}=", SecureDBFields::Crypto.encrypt(normalized, key: enc_key, aad: SecureDBFields::Crypto.aad(table_for_aad, field_name, uid), key_id: key_id))
          public_send("#{blind_index}=", SecureDBFields::Crypto.blind_index(normalized, key: bidx_key))
        end

        define_singleton_method("#{name}_blind_index_for") do |value|
          normalized = normalizer.call(value)
          return nil if normalized.nil?
          SecureDBFields::Crypto.blind_index(normalized, key: keyring.blind_index_key(domain))
        end
      end
    end
  end
end
