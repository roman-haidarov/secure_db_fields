# frozen_string_literal: true

require "mkmf"

abort "OpenSSL headers are required" unless have_header("openssl/evp.h")
abort "OpenSSL libcrypto is required" unless have_library("crypto", "EVP_aes_256_gcm")

$CFLAGS << " -std=c99 -Wall -Wextra -Werror=implicit-function-declaration"
create_makefile("secure_db_fields/secure_db_fields")
