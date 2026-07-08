# SecureDBFields samples

Команды запускаются из корня проекта.

## Подготовка

```bash
bundle install
bundle exec rake compile
```

## Ruby hot paths

```bash
bundle exec ruby samples/ruby_encrypt_hot_path.rb
bundle exec ruby samples/ruby_decrypt_hot_path.rb
bundle exec ruby samples/ruby_roundtrip_hot_path.rb

bundle exec ruby samples/ruby_blind_index_hot_path.rb
bundle exec ruby samples/ruby_blind_index_many_hot_path.rb
bundle exec ruby samples/ruby_blind_index_many_packed_hot_path.rb

bundle exec ruby samples/ruby_phone_exact_bidx_hot_path.rb
bundle exec ruby samples/ruby_phone_exact_bidx_many_hot_path.rb
bundle exec ruby samples/ruby_phone_exact_bidx_many_packed_hot_path.rb

PREFIX_DIGITS=7 bundle exec ruby samples/ruby_phone_prefix_bidx_hot_path.rb
PREFIX_DIGITS=7 bundle exec ruby samples/ruby_phone_prefix_bidx_many_packed_hot_path.rb

bundle exec ruby samples/ruby_envelope_parse_hot_path.rb
```

## Ruby batch hot paths

```bash
bundle exec ruby samples/ruby_encrypt_many_hot_path.rb
bundle exec ruby samples/ruby_decrypt_many_hot_path.rb
bundle exec ruby samples/ruby_roundtrip_many_hot_path.rb
```

## Запуск с параметрами

```bash
DURATION=45 SLEEP_BEFORE_HOT_LOOP=10 PREHEAT_ITERATIONS=100 \
  bundle exec ruby samples/ruby_phone_exact_bidx_hot_path.rb
```

```bash
DURATION=45 SLEEP_BEFORE_HOT_LOOP=10 PREHEAT_ITERATIONS=100 BATCH_SIZE=512 \
  bundle exec ruby samples/ruby_blind_index_many_packed_hot_path.rb
```

```bash
DURATION=45 SLEEP_BEFORE_HOT_LOOP=10 PREHEAT_ITERATIONS=100 BATCH_SIZE=512 \
  bundle exec ruby samples/ruby_encrypt_many_hot_path.rb
```

## MySQL UDF hot paths

Exact phone bidx:

```bash
mysql your_db < samples/mysql_udf_phone_bidx_hot_path.sql
mysql your_db -e 'CALL sdf_phone_bidx_hot_loop(500000)'
```

Prefix phone bidx:

```bash
mysql your_db < samples/mysql_udf_phone_prefix_bidx_hot_path.sql
mysql your_db -e 'CALL sdf_phone_prefix_bidx_hot_loop(500000, 7)'
```

Decrypt:

```bash
bundle exec ruby samples/mysql_udf_prepare_decrypt_payload.rb
mysql your_db -e 'source /tmp/secure_db_fields_mysql_decrypt_payload.sql; source samples/mysql_udf_decrypt_hot_path.sql; CALL sdf_decrypt_hot_loop(500000);'
```

## macOS profiling

Для Ruby-скриптов команда `sample` печатается самим скриптом после запуска.

Для `mysqld`:

```bash
sample $(pgrep -n mysqld) 35 -f /tmp/secure_db_fields_mysql_udf.sample
filtercalltree /tmp/secure_db_fields_mysql_udf.sample | grep -E 'secure_db_fields|secure_phone|sdf_|HMAC|EVP_|AES|GCM|SHA256' | head -300
```
