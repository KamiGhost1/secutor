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

## Миграции v0.2+

Все аддитивные: только новые колонки (всегда nullable) и новые таблицы.

### 0002 — admin support

```sql
ALTER TABLE accounts     ADD COLUMN deactivated_at TEXT;
ALTER TABLE certificates ADD COLUMN revoked_by      TEXT;  -- 'account' | 'admin:<fp>' | 'admin:<fp>:ban'
ALTER TABLE certificates ADD COLUMN revoke_event_id TEXT;  -- группирует cascade-revoke за один ban

-- Индексы под admin фильтры и stats
CREATE INDEX IF NOT EXISTS idx_certs_issued      ON certificates(issued_at);
CREATE INDEX IF NOT EXISTS idx_certs_not_after   ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certs_revoked_at  ON certificates(revoked, revoked_at);
CREATE INDEX IF NOT EXISTS idx_certs_account_v   ON certificates(account_id, revoked, not_after);
CREATE INDEX IF NOT EXISTS idx_orders_created    ON orders(created_at);
CREATE INDEX IF NOT EXISTS idx_orders_status_ts  ON orders(status, created_at);
CREATE INDEX IF NOT EXISTS idx_authz_status      ON authorizations(status);
CREATE INDEX IF NOT EXISTS idx_chall_status      ON challenges(status);
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_log(action, ts);
CREATE INDEX IF NOT EXISTS idx_audit_target      ON audit_log(target);
```

Также расширены допустимые значения `accounts.status` (`'valid' | 'deactivated' | 'banned'`)
и `orders.status` (`'pending' | 'ready' | 'processing' | 'valid' | 'invalid' | 'expired'`).
Валидация — на уровне приложения (CHECK-constraint снять нельзя без
пересоздания таблицы).

### 0003 — server-managed DNS placements

```sql
CREATE TABLE IF NOT EXISTS dns_placements (
  id             TEXT PRIMARY KEY,
  challenge_id   TEXT NOT NULL,
  record_name    TEXT NOT NULL,           -- _acme-challenge.<id>
  record_value   TEXT NOT NULL,           -- TXT-значение (base64url thumbprint hash)
  provider_label TEXT NOT NULL,           -- 'rfc2136(srv zone)' / 'script(path)' / 'memory'
  placed_at      TEXT NOT NULL,
  cleaned_at     TEXT                     -- NULL пока запись активна в DNS-зоне
);
CREATE INDEX idx_dns_placements_ch   ON dns_placements(challenge_id);
CREATE INDEX idx_dns_placements_open ON dns_placements(cleaned_at);

ALTER TABLE orders ADD COLUMN dns_placement TEXT;  -- 'client' (default) | 'server-managed'
```

### 0004 — reissue jobs

```sql
CREATE TABLE IF NOT EXISTS reissue_jobs (
  id           TEXT PRIMARY KEY,
  scope        TEXT NOT NULL,             -- 'all-active' | 'by-account' | 'by-identifier-pattern'
  params_json  TEXT,                      -- {accountIds?, identifierPattern?}
  status       TEXT NOT NULL,             -- 'running' | 'done' | 'failed' | 'cancelled'
  total        INTEGER NOT NULL DEFAULT 0,
  done         INTEGER NOT NULL DEFAULT 0,
  failed       INTEGER NOT NULL DEFAULT 0,
  rate_per_sec INTEGER NOT NULL DEFAULT 10,
  started_at   TEXT NOT NULL,
  finished_at  TEXT,
  actor_fp     TEXT                       -- SHA-256 admin-cert fp
);
CREATE TABLE IF NOT EXISTS reissue_job_items (
  id          TEXT PRIMARY KEY,
  job_id      TEXT NOT NULL,
  cert_id     TEXT NOT NULL,
  status      TEXT NOT NULL,              -- 'pending' | 'done' | 'failed'
  error       TEXT,
  finished_at TEXT
);
CREATE INDEX idx_reissue_items_job ON reissue_job_items(job_id, status);
```

`certificates.pem` и `serial_hex` обновляются in-place при successful
resign — id, account_id, order_id остаются прежними. Это нужно, чтобы
ACME-клиенты, которые pollят `GET /cert/:id` (cert-manager так делает),
сразу видели свежий сертификат без необходимости создавать новый order.

### 0005 — денормализованные identifiers на сертификате

```sql
ALTER TABLE certificates ADD COLUMN identifiers_json TEXT;
CREATE INDEX IF NOT EXISTS idx_certs_idents ON certificates(identifiers_json);
```

JSON-массив строк (`["svc.lan.vpn","*.dev.lan.vpn"]`). Wildcards сохраняют
`*.`-префикс. Заполняется при `insertCert` (finalize + admin-issue);
для старых rows одноразовый backfill при старте — реконструирует
identifiers из `authorizations` через `order_id`.

Упрощает admin листинг: `SELECT * FROM certificates ...` без JOIN на
authz, фильтр `?identifier=X` → `identifiers_json LIKE '%"X"%'`.
Точный match (кавычки — границы JSON-строки); для wildcard'ов писать
`?identifier=*.foo.lan` явно.
