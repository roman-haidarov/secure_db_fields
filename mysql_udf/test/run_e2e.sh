#!/usr/bin/env bash
set -euo pipefail

DEFAULT_MYSQL_IMAGE="mysql:5.7.44@sha256:dab0a802b44617303694fb17d166501de279c3031ddeb28c56ecf7fcab5ef0da"
IMAGE="${SDF_MYSQL_IMAGE:-$DEFAULT_MYSQL_IMAGE}"
PLATFORM="${SDF_MYSQL_PLATFORM:-linux/amd64}"
WAIT_SECONDS="${SDF_MYSQL_WAIT_SECONDS:-120}"
CONTAINER="sdf-mysql57-e2e-${RANDOM}-${RANDOM}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPDIR="$(mktemp -d)"
ARCHIVE="$TMPDIR/secure_db_fields-mysql.tar.gz"
PACKED="$TMPDIR/packed"
BUNDLE_PARENT="/opt"
KEY_HEX_A="6161616161616161616161616161616161616161616161616161616161616161"
KEY_HEX_B="6262626262626262626262626262626262626262626262626262626262626262"
KEY_HEX_C="6363636363636363636363636363636363636363636363636363636363636363"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

ensure_ruby_extension() {
  (cd "$ROOT" && bundle exec rake compile)
}

prepare_packaged_gem() {
  rm -rf "$PACKED"
  mkdir -p "$PACKED"
  (cd "$ROOT" && gem build secure_db_fields.gemspec >/dev/null)
  gem unpack "$ROOT/secure_db_fields-0.1.1.gem" --target "$PACKED" >/dev/null
}

ruby_from_packaged() {
  ruby -I "$PACKED/secure_db_fields-0.1.1/lib" "$PACKED/secure_db_fields-0.1.1/exe/secure_db_fields" "$@"
}

build_deployment_bundle() {
  ruby_from_packaged db package mysql --output "$ARCHIVE" --force
  test -s "$ARCHIVE"
  tar -tzf "$ARCHIVE" | grep -Fx 'secure_db_fields-mysql-0.1.1/Makefile' >/dev/null
  tar -tzf "$ARCHIVE" | grep -Fx 'secure_db_fields-mysql-0.1.1/bin/install' >/dev/null
  if tar -tzf "$ARCHIVE" | grep -E '/\.DS_Store$' >/dev/null; then
    echo 'deployment bundle must not contain .DS_Store' >&2
    exit 2
  fi
}

install_mysql_build_tools() {
  docker exec -u 0 "$CONTAINER" sh -ceu '
    if command -v yum >/dev/null 2>&1; then
      yum install -y gcc make binutils tar gzip openssl-devel
    elif command -v microdnf >/dev/null 2>&1; then
      microdnf install -y gcc make binutils tar gzip openssl-devel
    elif command -v apt-get >/dev/null 2>&1; then
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential tar gzip libssl-dev
    else
      echo "no supported package manager in MySQL container" >&2
      exit 2
    fi
    command -v cc
    command -v make
    test -f /usr/include/openssl/evp.h || find /usr/include -name evp.h | head -1 | grep -q .
  '
}

install_bundle_on_db_host() {
  local bundle_root="$BUNDLE_PARENT/secure_db_fields-mysql-0.1.1"
  docker cp "$ARCHIVE" "$CONTAINER:/tmp/secure_db_fields-mysql.tar.gz"
  docker exec -u 0 "$CONTAINER" sh -ceu '
    rm -rf /opt/secure_db_fields-mysql-0.1.1
    tar -xzf /tmp/secure_db_fields-mysql.tar.gz -C /opt
    cd /opt/secure_db_fields-mysql-0.1.1
    make verify
    make doctor
    make install
    make enable
    make status
  '
}

write_key_file() {
  docker exec -u 0 "$CONTAINER" sh -ceu "
    install -d -m 0750 -o root -g mysql /etc/secure_db_fields
    cat > /etc/secure_db_fields/keys.env <<'EOF'
SDF_ACTIVE_KEY_ID=1
SDF_ENC_KEY_1_HEX=$KEY_HEX_A
SDF_BIDX_KEY_HEX=$KEY_HEX_B
SDF_BIDX_PHONE_KEY_HEX=$KEY_HEX_B
SDF_BIDX_PHONE_P7_KEY_HEX=$KEY_HEX_C
EOF
    chown root:mysql /etc/secure_db_fields/keys.env
    chmod 0640 /etc/secure_db_fields/keys.env
  "
}

make_fixture_sql() {
  ruby -I "$ROOT/lib" <<'RUBY' > "$TMPDIR/fixture.env"
require "securerandom"
require "secure_db_fields"
enc_key = "a" * 32
phone_key = "b" * 32
p7_key = "c" * 32
uid = SecureRandom.random_bytes(16)
phone = "+77771234567"
aad = SecureDBFields::Crypto.aad("clients", "phone", uid)
envelope = SecureDBFields::Crypto.encrypt(phone, key: enc_key, aad: aad, key_id: 1)
puts "UID_HEX=#{uid.unpack1("H*")}"
puts "PHONE=#{phone}"
puts "ENC_HEX=#{envelope.unpack1("H*")}"
puts "BIDX_HEX=#{SecureDBFields::Crypto.phone_blind_index(phone, key: phone_key).unpack1("H*")}"
puts "P7_HEX=#{SecureDBFields::Crypto.phone_prefix_blind_index(phone, prefix_digits: 7, key: p7_key).unpack1("H*")}"
RUBY
  source "$TMPDIR/fixture.env"
  cat > "$TMPDIR/app.sql" <<SQL
DROP DATABASE IF EXISTS app;
DROP DATABASE IF EXISTS admin;
CREATE DATABASE app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE admin CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE app;
CREATE TABLE clients (
  id INT PRIMARY KEY,
  secure_row_uid BINARY(16) NOT NULL,
  phone_enc LONGBLOB NOT NULL,
  phone_bidx BINARY(32) NOT NULL,
  phone_bidx_p7 BINARY(32) NOT NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_clients_phone_bidx(phone_bidx),
  INDEX idx_clients_phone_bidx_p7(phone_bidx_p7)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO clients VALUES (1, UNHEX('$UID_HEX'), UNHEX('$ENC_HEX'), UNHEX('$BIDX_HEX'), UNHEX('$P7_HEX'), '2026-07-08 12:00:00');
SQL
  ruby_from_packaged db view mysql \
    --table app.clients \
    --field phone:phone_enc \
    --uid-column secure_row_uid \
    --view admin.clients_readable \
    --columns id,created_at \
    --output "$TMPDIR/view.sql" >/dev/null
}

q() {
  docker exec "$CONTAINER" mysql --default-character-set=utf8mb4 --batch --skip-column-names --raw -e "$1"
}

assert_eq() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [ "$actual" != "$expected" ]; then
    echo "FAIL $label: expected [$expected], got [$actual]" >&2
    exit 1
  fi
  echo "ok - $label"
}

assert_contains() {
  local label="$1"
  local haystack="$2"
  local needle="$3"
  if ! printf '%s' "$haystack" | grep -Fq "$needle"; then
    echo "FAIL $label: missing [$needle] in [$haystack]" >&2
    exit 1
  fi
  echo "ok - $label"
}

ensure_ruby_extension
prepare_packaged_gem
build_deployment_bundle

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --platform "$PLATFORM" -d --name "$CONTAINER" -e MYSQL_ALLOW_EMPTY_PASSWORD=1 "$IMAGE" \
  --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci >/dev/null

echo "waiting for mysqld in $IMAGE..."
deadline=$(( $(date +%s) + WAIT_SECONDS ))
until docker exec "$CONTAINER" mysqladmin ping --silent 2>/dev/null; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "mysqld did not become ready within ${WAIT_SECONDS}s" >&2
    docker logs "$CONTAINER" >&2 || true
    exit 1
  fi
  sleep 2
done

install_mysql_build_tools
write_key_file
install_bundle_on_db_host
make_fixture_sql

docker exec -i "$CONTAINER" mysql --default-character-set=utf8mb4 < "$TMPDIR/app.sql"
docker exec -i "$CONTAINER" mysql --default-character-set=utf8mb4 < "$TMPDIR/view.sql"

version="$(q 'SELECT secure_db_fields_version();')"
assert_contains 'version' "$version" 'secure_db_fields 0.1.1'
assert_eq 'valid envelope' '1' "$(q 'SELECT secure_db_fields_is_valid_envelope(phone_enc) FROM app.clients WHERE id=1;')"
assert_eq 'envelope key id' '1' "$(q 'SELECT secure_db_fields_envelope_key_id(phone_enc) FROM app.clients WHERE id=1;')"
assert_eq 'decrypt field' '+77771234567' "$(q "SELECT secure_db_fields_decrypt_field(phone_enc, 'clients', 'phone', secure_row_uid) FROM app.clients WHERE id=1;")"
assert_eq 'admin view decrypt' '+77771234567' "$(q 'SELECT phone FROM admin.clients_readable WHERE id=1;')"
assert_eq 'exact bidx indexed search' '1' "$(q "SELECT COUNT(*) FROM app.clients WHERE phone_bidx = secure_phone_bidx('+77771234567');")"
assert_eq 'prefix bidx indexed search' '1' "$(q "SELECT COUNT(*) FROM app.clients WHERE phone_bidx_p7 = secure_phone_prefix_bidx('+77771234567', 7);")"
assert_eq 'invalid phone bidx is null' '1' "$(q "SELECT secure_phone_bidx('87771234567') IS NULL;")"
assert_eq 'wrong aad decrypt is null' '1' "$(q "SELECT secure_db_fields_decrypt_field(phone_enc, 'clients', 'email', secure_row_uid) IS NULL FROM app.clients WHERE id=1;")"

explain_exact="$(q "EXPLAIN SELECT id FROM app.clients WHERE phone_bidx = secure_phone_bidx('+77771234567');")"
assert_contains 'EXPLAIN uses exact bidx index' "$explain_exact" 'idx_clients_phone_bidx'
explain_prefix="$(q "EXPLAIN SELECT id FROM app.clients WHERE phone_bidx_p7 = secure_phone_prefix_bidx('+77771234567', 7);")"
assert_contains 'EXPLAIN uses prefix bidx index' "$explain_prefix" 'idx_clients_phone_bidx_p7'

docker exec -u 0 "$CONTAINER" sh -ceu 'cd /opt/secure_db_fields-mysql-0.1.1 && CONFIRM=REMOVE_SECURE_DB_FIELDS make uninstall'
assert_eq 'functions removed' '0' "$(q "SELECT COUNT(*) FROM mysql.func WHERE dl = 'secure_db_fields_mysql.so';")"

echo 'secure_db_fields MySQL 5.7 UDF e2e: ok'
