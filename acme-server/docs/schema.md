# Схема данных ACME-стейта

Отдельный SQLite-файл (`acme.db`) в writable томе. Никаких изменений в CA-сторе secutor.

Все ID — ULID (сортируемые, без коллизий). Все таймстампы — ISO-8601 UTC.

## `accounts`

| поле           | тип    | примечание                                           |
|----------------|--------|------------------------------------------------------|
| id             | TEXT   | PK. URL: `/acct/<id>`                                |
| jwk_thumbprint | TEXT   | UNIQUE. SHA256 от JWK (RFC 7638), для поиска         |
| jwk_json       | TEXT   | публичный ключ аккаунта                              |
| contact_json   | TEXT   | массив `mailto:` URI                                 |
| status         | TEXT   | `valid` / `deactivated` / `revoked`                  |
| terms_agreed   | INT    | 0/1                                                  |
| allow_list_json| TEXT   | NULL или массив паттернов (расширение, см. architecture) |
| created_at     | TEXT   |                                                      |

## `orders`

| поле            | тип  | примечание                                                 |
|-----------------|------|------------------------------------------------------------|
| id              | TEXT | PK                                                         |
| account_id      | TEXT | FK → accounts.id                                           |
| status          | TEXT | `pending`/`ready`/`processing`/`valid`/`invalid`           |
| identifiers_json| TEXT | `[{type:"dns", value:"foo.lan"}, ...]`                     |
| not_before      | TEXT | nullable, запрошенное клиентом                             |
| not_after       | TEXT | nullable                                                   |
| expires_at      | TEXT | когда order протухнет, если не финализирован               |
| error_json      | TEXT | nullable, ACME problem document при invalid                |
| certificate_id  | TEXT | FK → certificates.id, заполняется после finalize           |
| csr_der         | BLOB | nullable, сохраняем для аудита                             |
| created_at      | TEXT |                                                            |

Индексы: `(account_id, status)`, `(expires_at)`.

## `authorizations`

| поле          | тип  | примечание                                            |
|---------------|------|-------------------------------------------------------|
| id            | TEXT | PK                                                    |
| order_id      | TEXT | FK → orders.id                                        |
| identifier_type | TEXT | `dns`                                               |
| identifier_value| TEXT | например `foo.lan` или `*.foo.lan`                  |
| wildcard      | INT  | 0/1, дублирует префикс `*.` для индексации            |
| status        | TEXT | `pending`/`valid`/`invalid`/`expired`/`revoked`       |
| expires_at    | TEXT |                                                       |
| created_at    | TEXT |                                                       |

Индексы: `(order_id)`, `(identifier_value, status)`.

## `challenges`

| поле          | тип  | примечание                                            |
|---------------|------|-------------------------------------------------------|
| id            | TEXT | PK                                                    |
| authz_id      | TEXT | FK → authorizations.id                                |
| type          | TEXT | `dns-01` / `http-01`                                  |
| token         | TEXT | base64url, ≥128 бит энтропии                          |
| status        | TEXT | `pending`/`processing`/`valid`/`invalid`              |
| validated_at  | TEXT | nullable                                              |
| error_json    | TEXT | nullable, problem document при invalid                |
| attempts      | INT  | счётчик попыток валидации                             |
| next_check_at | TEXT | для воркера: когда снова пробовать                    |
| created_at    | TEXT |                                                       |

Индексы: `(authz_id)`, `(status, next_check_at)` — для воркера.

## `nonces`

| поле       | тип  | примечание                                  |
|------------|------|---------------------------------------------|
| value      | TEXT | PK. base64url(16 байт)                      |
| expires_at | TEXT | TTL, например 5 мин                         |
| created_at | TEXT |                                             |

Periodically `DELETE WHERE expires_at < now()`. Альтернатива — держать в памяти (Map), но при рестарте инвалидируются все pending-запросы клиентов; для надёжности — в БД.

## `certificates`

| поле           | тип  | примечание                                              |
|----------------|------|---------------------------------------------------------|
| id             | TEXT | PK. URL: `/cert/<id>`                                   |
| order_id       | TEXT | FK → orders.id                                          |
| account_id     | TEXT | FK → accounts.id (денормализация для запросов)          |
| serial_hex     | TEXT | UNIQUE                                                  |
| pem            | TEXT | leaf cert                                               |
| chain_pem      | TEXT | issuer chain без leaf                                   |
| not_before     | TEXT |                                                         |
| not_after      | TEXT |                                                         |
| revoked        | INT  | 0/1                                                     |
| revoked_at     | TEXT | nullable                                                |
| revocation_reason | INT | nullable, RFC 5280 reasonCode                         |
| issued_at      | TEXT |                                                         |

Индексы: `(account_id, issued_at)`, `(revoked, not_after)` — для генерации CRL.

## `audit_log`

| поле        | тип  | примечание                                              |
|-------------|------|---------------------------------------------------------|
| id          | TEXT | PK                                                      |
| ts          | TEXT |                                                         |
| actor_type  | TEXT | `account` / `system` / `admin`                          |
| actor_id    | TEXT | nullable                                                |
| action      | TEXT | `account.create`, `order.create`, `challenge.validate`, `cert.issue`, `cert.revoke`, ... |
| target      | TEXT | id ресурса                                              |
| ip          | TEXT | nullable                                                |
| details_json| TEXT | nullable                                                |

Append-only. Никогда не апдейтим, не удаляем (кроме ретеншена по политике).

## Жизненный цикл и чистка

- `orders` в `pending`/`invalid` старше N дней → удалять каскадом (authz, challenges).
- `nonces` с истёкшим `expires_at` → удалять каждые несколько минут.
- `certificates` — никогда не удаляем. Источник правды по выпущенному.
- `audit_log` — по политике ретеншена (например, 1 год), отдельной утилитой.
