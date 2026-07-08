# secure_db_fields — финальное решение (locked)

Заменяет черновой design-док. Это закрывающее решение с зафиксированными
границами для MySQL 5.7 + Ruby/Rails. Целевая совместимость: Ruby >= 2.7.1, MySQL 5.7. Крипто-ядро и архитектура заморожены;
единственный оставшийся вход — инвентаризация запросов (см. §10).

---

## 1. Вердикт

Пишем **свой узкий field-encryption слой по архитектуре multi_compress**, без
собственной криптографии: рандомизированный AEAD + keyed blind index +
MySQL UDF/view + миграционный контракт. Не готовый продукт, не pq_crypto,
не property-preserving.

Форма: небольшой **явный конфиг для конкретных полей** (телефон, email, ИИН,
ФИО), а не DSL-генератор. Кодогенерацию/платформу заводить только если впереди
десятки полей — иначе это лишняя поверхность.

---

## 2. Что отвергнуто и почему (проверено по первоисточникам)

| Вариант | Причина отказа |
|---|---|
| pq_crypto | KEM/подписи, а не field-encryption. Симметричная задача. Плюс сам гем не аудирован. |
| MySQL `AES_ENCRYPT` | Дефолт `block_encryption_mode` = `aes-128-ecb` (ECB); не AEAD. |
| TDE / InnoDB at-rest | Защищает физические файлы, но не логический `mysqldump`/`SELECT INTO OUTFILE`. |
| Acra CE | По их докам: не хранит search-хеши отдельно от ciphertext → поиск требует functional indexes, которых в MySQL 5.7 нет; LIKE — только Enterprise. |
| D'Amo / MyDiamo | Заявляют «keeps the order + range search» = property-preserving; вскрывается inference-атаками (Naveed–Kamara–Wright, Lacharité–Minaud–Paterson). Требует security review. |
| CipherStash | PostgreSQL + proxy/EQL. Не MySQL. |
| SQL Server Always Encrypted | LIKE/range только через secure enclaves (другой движок + TEE). |
| MongoDB Queryable Encryption | Другой движок; prefix/suffix/substring — public preview, не для прода. |
| Lockbox / blind_index / CipherSweet | Хорошая модель (мы её и берём), но не дают MySQL UDF, admin view, DBA bundle. |
| generated column bidx через UDF | В MySQL 5.7 stored/loadable функции в generated column запрещены (есть verified crash bug). |
| OPE / FPE / range-preserving | Property-preserving leakage. Вне scope. |

---

## 3. Крипто-ядро

```
encryption:  AES-256-GCM (OpenSSL), рандомизированный nonce, envelope
search:      blind index = HMAC-SHA256(bidx_key, normalized_value)
keys:        отдельные ключи под шифрование и под каждый blind index; HKDF из мастера
AAD:         "table.column:" || secure_row_uid   (не хранится, восстанавливается)
envelope:    magic "MCEN" | version | alg_id | key_id | nonce(12) | tag(16) | ciphertext
```

Nonce: per-column ключ → на объёме одной колонки далеко под лимитом 2³² случайного
GCM-nonce, отдельный XChaCha/counter не нужен.

Общий C-core компилируется в Ruby-ext и в MySQL-UDF (как MCDB в multi_compress).

---

## 4. Схема колонок (пример clients.phone)

```sql
secure_row_uid   BINARY(16)   -- генерится в Ruby ДО INSERT, неизменяем, обязателен для AAD
phone_enc        VARBINARY    -- envelope
phone_bidx       BINARY(32)   -- exact / UNIQUE
-- prefix/suffix колонки добавляются ТОЛЬКО по инвентаризации (§10), напр.:
-- phone_bidx_p7 BINARY(32)
INDEX idx_clients_phone_bidx (phone_bidx)
```

- Физические колонки, не generated. bidx считает приложение/backfill.
- `NULL` value → `NULL` bidx (несколько пустых не конфликтуют под UNIQUE).
- Нормализация коллизий: два ввода, канонизирующихся в один E.164, дадут одно
  UNIQUE-значение — принять семантику заранее.

---

## 5. Контракт поиска + реестр утечек (leakage ledger)

Каждый режим поиска несёт именованную, принятую утечку. Ничего сверх объявленного
не поддерживаем.

| Режим | Как | Утечка в дампе БЕЗ ключа | Вердикт |
|---|---|---|---|
| exact (полное значение) | `bidx = HMAC(E.164)` | для телефона ≈ нет (значения почти уникальны); видно равенство одинаковых номеров | безопасно |
| `IN (...)`, `UNIQUE` | тот же bidx | то же | безопасно |
| `JOIN` по bidx | общий ключ между таблицами | кросс-табличное равенство поля | ок, если задумано |
| prefix длины N | `bidx_pN = HMAC(первые N цифр)` | низкая кардинальность: видно, какие строки делят N-значный префикс | принять **по каждой длине**, только если реально используется |
| suffix / last4 | `HMAC(последние 4)` | ОЧЕНЬ низкая кардинальность (≤10⁴ классов): сильный equality/frequency-сигнал | **highest-risk — обосновать или выкинуть** |
| `LIKE '%x%'` (инфикс) | — | требует ngram/bloom/proxy | **вне scope** |
| `ORDER BY` / range | — | property-preserving → восстановление plaintext | **вне scope** |

Общее: при утечке **ключа** (компрометация хоста) любой bidx перебираем словарём
(телефон — перечислимое пространство). Вся защита держится на «ключ вне дампа».

---

## 6. Контракт доступа админов (DBeaver/DataGrip)

**View — только для просмотра**, фильтр по неприватным колонкам:
```sql
CREATE VIEW admin_clients_readable AS
SELECT id, secure_decrypt_phone(phone_enc, secure_row_uid) AS phone, created_at
FROM clients;
-- SELECT ... WHERE id = 123;   -- ок
```
Не давать `SELECT * FROM admin_clients_readable` без фильтра: это массовый decrypt
(и `INTO OUTFILE` из view выгрузит plaintext). Ограничить грантами/лимитом.

**Поиск — только через официальный контракт** (индекс по bidx, decrypt на проекции):
```sql
CALL admin_find_client_by_phone('+77771234567');
-- или query-template:
SELECT id, secure_decrypt_phone(phone_enc, secure_row_uid) AS phone
FROM clients
WHERE phone_bidx = secure_phone_bidx('+77771234567');
```
`WHERE phone = ...` по decrypt-view — запрещённый паттерн (decrypt-scan; view не
индексируется, TEMPTABLE не использует индексы базовой таблицы).

---

## 7. Ключи и принятая граница угроз

```
Ключи:  /etc/secure_db_fields/keys.json (owner root, group mysql, mode 0640)
        или keyring/KMS. Вне любой таблицы, НИКОГДА в SQL-аргументе.
В БД:   ciphertext, key_id, bidx, secure_row_uid, metadata. Ключей нет.
```

**Явно принятая модель (записать в контракт, не подразумевать):**
- Утёк дамп/таблица БЕЗ ключей → приватные поля не читаются. ✔ (цель)
- Утёк дамп + файл ключа / компрометация хоста → защита пробита. ✘ (вне модели)
- Админ с доступом к decrypt-view/UDF → видит plaintext. Это разрешённый пользователь.
- decrypt-UDF — оракул для любого, кто может его вызвать на живом сервере.
  Граница контроля — доступ к колонкам/view/процедурам/файлу ключа
  (у loadable UDF нет `GRANT EXECUTE`).

Ротация: `key_id`/версии в envelope; новые записи под новым ключом, старые
читаются старым; rewrap лениво.

---

## 8. Нормализация — часть контракта

Канонизация в приложении **до** шифрования и bidx; DB-helper принимает уже E.164.
```
8 777 123 45 67 / +7 (777) 123-45-67  →  +77771234567
secure_phone_bidx('+77771234567')  -- ok
secure_phone_bidx('8 777 ...')     -- error, а не «угадывание»
```
Нормализатор — в общем C-core (байт-в-байт одинаково в Ruby и UDF), иначе bidx
разъедутся. Префиксный поиск нормализуется теми же правилами (иначе `8777%` и
`+7777%` дадут разные `bidx_pN`), и `bidx_pN` отвечает ровно на длину N.

---

## 9. Миграция (dual-write, zero-downtime)

```
1. Инвентаризация запросов (§10) → финальный список bidx-колонок.
2. ALTER TABLE: secure_row_uid, *_enc, *_bidx(+ объявленные), индексы. Все NULL.
3. Backfill батчами: uid + enc + bidx из открытого значения. Идемпотентно.
4. Dual-write: приложение пишет старую колонку И новые; чтение/поиск → на bidx.
5. Admin views + search procedures + гранты + отдельные DB-пользователи.
6. Верификация: counts, sample-decrypt, паритет старый LIKE vs новый bidx, EXPLAIN.
7. Бэкап → DROP старых plaintext-колонок (точка невозврата).
8. (опц.) UNIQUE на bidx после чистки дублей/NULL.
```
Backfill обязан проставить `secure_row_uid` всем старым строкам; копирование строки
без переноса uid ломает AAD.

---

## 10. Единственный оставшийся вход: инвентаризация запросов

Схема bidx-колонок — это **функция от реальных запросов**. До её сбора список
`*_bidx_p*`/`last4` — гадание. Собрать из `general_log`/`slow_log`/кода приложения
по каждому приватному полю:

```
phone = ?           → exact bidx           (безопасно)
phone IN (...)       → exact bidx           (безопасно)
UNIQUE(phone)        → exact bidx unique    (безопасно)
JOIN ON phone        → общий bidx-домен     (равенство кросс-таблиц)
phone LIKE '777%'    → bidx_pN конкретной N (низкокардинальная утечка)
phone LIKE '%1234'   → last4                (highest-risk — обосновать/выкинуть)
phone LIKE '%777%'   → decrypt-scan / вне scope
ORDER BY / range     → вне scope
```

Итог инвентаризации = точный список колонок и индексов, который лочит §4–§5.

---

## 11. Границы (окончательно)

```
Поддерживаем:  Ruby encrypt/decrypt/search; MySQL decrypt-UDF; admin views;
               exact/IN/UNIQUE через blind index; объявленные prefix/lastN;
               JOIN по bidx-домену; dual-write backfill; key_id/версии; AAD.
Не поддерживаем: произвольный LIKE '%x%'; ORDER BY/range по plaintext;
               «любой старый SQL работает как раньше»; generated bidx через UDF;
               ключи в БД или в SQL; pq_crypto/KEM; deterministic/OPE/FPE как основа.
```
