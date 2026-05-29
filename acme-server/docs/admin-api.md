# Admin API (mTLS)

Параллельный fastify-инстанс на отдельном порту (`config.admin.listen`).
Принимает **только** mTLS-аутентифицированные соединения — единственное
исключение — опциональный `GET /admin/v1/auth-policy` (включается
`publishPolicy: true`).

Все эндпоинты под `/admin/v1/`. Ответы JSON, ошибки —
`{"error": "<code>", "detail": "..."}`.

> **Сначала setup, потом reference.** Если admin API ещё не поднят —
> начни с [admin-setup.md](admin-setup.md) (пошагово: сгенерить
> сертификаты, написать `config.yaml`, перезапустить, проверить
> curl'ом, подключить TUI). Здесь — только описание уже работающих
> эндпоинтов.

## Конфигурация

```yaml
admin:
  listen: "0.0.0.0:8444"
  serverTls:
    certFile: /etc/secutor-acme/admin-server.crt
    keyFile:  /etc/secutor-acme/admin-server.key
  trust:
    # Совпадение по любому из правил даёт доступ; выигрывает самая высокая роль
    fingerprints:
      - sha256: "abcd...ef"
        role: owner
        label: "ops-admin (laptop)"
      - sha256: "1234...56"
        role: operator
        label: "ci-runner-1"
    cas:
      - caFile: /etc/secutor-acme/admin-ca.pem
        subjectMatch: "OU=NOC"
        role: operator
      - caFile: /etc/secutor-acme/corp-mdm.pem
        subjectMatch: "OU=ops"
        role: viewer
    publishPolicy: false        # выставить true, чтобы /auth-policy был доступен анонимно
  banMode: cascade              # 'cascade' (default) | 'soft'
```

Серверный сертификат admin-API — независим от ACME-сертификата (можно
self-signed). Клиент TUI всё равно проверяет его pin-fingerprint, не
цепочку.

## Роли

- `viewer` — read everything.
- `operator` — то же + revoke сертификатов, admin-issue (запуск выпусков).
- `owner` — то же + ban аккаунтов (каскадный revoke), patch аккаунтов,
  stage/promote/rollback CA, запуск reissue job, cancel job.

## Эндпоинты

### Общие

| Метод | Путь | Роль | Что |
|---|---|---|---|
| GET | `/admin/v1/info` | viewer | версия, fp CA, базовая статистика |
| GET | `/admin/v1/health` | — | live/ready (не требует роли) |
| GET | `/admin/v1/auth-policy` | — (opt-in) | публикация trust-policy для auto-discover в TUI |
| GET | `/admin/v1/metrics` | viewer | Prometheus text |

### Сертификаты

| Метод | Путь | Роль |
|---|---|---|
| GET | `/admin/v1/certificates?[account_id=][&revoked=true\|false][&identifier=][&issued_after=][&issued_before=][&expires_before=][&limit=][&offset=]` | viewer |
| GET | `/admin/v1/certificates/:id` | viewer |

Каждая запись листинга включает `identifiers: string[]` — DNS SANs из
order'а (wildcards с префиксом `*.`), денормализовано в
`certificates.identifiers_json` миграцией 0005. Сам `pem` опущен
(`pem_omitted: true`); полный PEM — через details endpoint.

Фильтр `?identifier=svc.lan.vpn` ищет **точный** match по identifier
из массива (через `LIKE '%"svc.lan.vpn"%'` — кавычки границы JSON
строки). `?identifier=lan.vpn` НЕ матчит `svc.lan.vpn` — для wildcard
запросов пишите `?identifier=*.lan.vpn` явно.

Details (`GET /admin/v1/certificates/:id`) возвращает полную CertRow
+ `identifiers: string[]` + `pem` + `chain_pem`. Поле
`identifiers_json` (raw) наружу не торчит.
| POST | `/admin/v1/certificates/:id/revoke` body `{reason}` | operator |
| POST | `/admin/v1/certificates/issue` body см. ниже | operator |

`POST /certificates/issue` body:

```json
{
  "identifiers": [{"type": "dns", "value": "svc.lan.vpn"}],
  "csr": "<base64url DER>",            // ИЛИ subject+keyAlgorithm для server-generated
  "subject": {"commonName": "svc.lan.vpn"},
  "keyAlgorithm": "ecdsa-p256",
  "notAfterDays": 90
}
```

Если CSR не передан — сервер сам генерит keypair и возвращает PEM ключа
(`generated_key_pem`) **только в ответе**, ключ на диске не остаётся.
Удобно через TUI забрать новый key+cert и положить в локальный контекст
через `keys import`.

### Аккаунты

| Метод | Путь | Роль |
|---|---|---|
| GET | `/admin/v1/accounts?[limit][offset]` | viewer |
| PATCH | `/admin/v1/accounts/:id` body `{status?, allow_list?, contact?}` | owner |
| POST | `/admin/v1/accounts/:id/ban` body `{reason?, comment?}` | owner |
| POST | `/admin/v1/accounts/:id/unban` | owner |

**Ban** атомарно (одна SQLite-транзакция):
1. Аккаунт → `status='banned'`.
2. Все валидные не-истёкшие сертификаты этого аккаунта отзываются с
   `reason=privilegeWithdrawn` (default) + `revoked_by='admin:<fp>:ban'`
   + `revoke_event_id=<auditId>`.
3. Все открытые ордера → `status='invalid'`, `error_json={type:"secutor:accountBanned"}`.
4. В `audit_log` пишется `action='account.ban'` + по одной
   `action='cert.revoke.cascade'` записи на каждый отозванный серт.

**Unban** возвращает только статус — отозванные сертификаты не
восстанавливаются (CRL уже мог разойтись по relying parties).

Конфиг `admin.banMode: 'soft'` отключает каскад: ban только меняет
статус + cancel'ит открытые ордера, без revoke серти.

### Ордера, аудит, стейт

| Метод | Путь | Роль |
|---|---|---|
| GET | `/admin/v1/orders?[status][account_id][since][until][limit][offset]` | viewer |
| GET | `/admin/v1/audit?[action][actor_id][target][since][limit][offset]` | viewer |

### Stats

Все принимают `?since=<iso>&until=<iso>` (default: последние 30 дней,
`until` — `now + 60s` для слака).

| Метод | Путь | Что |
|---|---|---|
| GET | `/admin/v1/stats/orders[?bucket=day\|hour]` | total/by-status/success_rate + временные корзины |
| GET | `/admin/v1/stats/failures` | total invalid, top problem types, by-challenge-type, top failing identifiers |
| GET | `/admin/v1/stats/issuance[?bucket=day\|hour]` | временной ряд issued/revoked |

### CA bridge (rotation)

Подробно — [ca-rotation.md](ca-rotation.md).

| Метод | Путь | Роль |
|---|---|---|
| GET | `/admin/v1/ca` | viewer |
| GET | `/admin/v1/ca/chain` | viewer |
| POST | `/admin/v1/ca/verify` body `{nonce: base64url}` | operator |
| POST | `/admin/v1/ca/stage` body `{cert_pem, key_pem, chain_pem}` | owner |
| GET | `/admin/v1/ca/staged` | viewer |
| DELETE | `/admin/v1/ca/staged` | owner |
| POST | `/admin/v1/ca/promote` | owner |
| POST | `/admin/v1/ca/rollback` | owner |

### Reissue jobs

| Метод | Путь | Роль |
|---|---|---|
| POST | `/admin/v1/jobs/reissue` body `{scope, ratePerSec?, accountIds?, identifierPattern?}` | owner |
| GET | `/admin/v1/jobs/:id` | viewer |
| POST | `/admin/v1/jobs/:id/cancel` | owner |

## Аудит и observability

Каждая мутирующая admin-операция (revoke, ban, unban, account.update,
ca.stage / .promote / .rollback / .verify, reissue.start / .cancel,
cert.issue.admin) пишется в `audit_log` с `actor_type='admin'`,
`actor_id = SHA-256(peer-cert DER)`. Можно фильтровать по этому
fingerprint'у — каждый admin отличим.

## Совместимость с RFC 8555

Admin namespace полностью отделён. Стандартные ACME-клиенты (certbot,
acme.sh, cert-manager, Traefik) ничего о нём не знают — для них всё, что
не `/admin/`, работает как раньше.

Статус `banned` для RFC-клиентов рендерится как `deactivated` (RFC 8555
не знает другого терминального значения).
