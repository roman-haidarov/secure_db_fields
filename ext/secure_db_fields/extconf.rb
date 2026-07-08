# frozen_string_literal: true

require "mkmf"

abort "OpenSSL headers are required" unless have_header("openssl/evp.h")
abort "OpenSSL libcrypto is required" unless have_library("crypto", "EVP_aes_256_gcm")

clang_only_wno = %w[
  -Wno-self-assign
  -Wno-parentheses-equality
  -Wno-constant-logical-operand
]
if RbConfig::CONFIG["CC"].to_s !~ /clang/i
  $warnflags = $warnflags.to_s.split.reject { |flag| clang_only_wno.include?(flag) }.join(" ")
end

$CFLAGS << " -std=c99 -Wall -Wextra -Werror=implicit-function-declaration"
$CFLAGS << " -DOPENSSL_SUPPRESS_DEPRECATED"

create_makefile("secure_db_fields/secure_db_fields")
