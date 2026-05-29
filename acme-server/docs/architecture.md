# Архитектура

## Компоненты

```
┌──────────────────────────────────────────────────────────┐
│                     secutor-acme (Node)                  │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  HTTP    │→ │  ACME    │→ │ Challenge│→ │  Signer  │ │
│  │  (fastify)│ │  router  │  │ validator│  │  (forge) │ │
│  └──────────┘  └──────────┘  └──────────┘  └────┬─────┘ │
│        │            │             │             │       │
│        │       ┌────▼─────────────▼────┐   ┌────▼─────┐ │
│        │       │   ACME state (SQLite) │   │ CA store │ │
│        │       │   /var/lib/.../acme.db│   │ (ro mount)│
│        │       └───────────────────────┘   └──────────┘ │
│        │                                                │
│        └─→  DNS-01 resolver(s) ──→ внутр./публичный DNS │
└──────────────────────────────────────────────────────────┘
```

- **HTTP**: fastify + плагин `jose` для проверки JWS-подписи каждого запроса (RFC 8555 §6.2).
- **ACME router**: эндпоинты `directory`, `newNonce`, `newAccount`, `newOrder`, `authz/:id`, `chall/:id`, `finalize`, `cert/:id`, `revokeCert`, `keyChange`.
- **Challenge validator**: воркер, который для каждого pending-challenge выполняет проверку (DNS lookup или HTTP-запрос) и обновляет статус.
- **Signer**: тонкая обёртка над `src/certs/signing.ts`. Получает CSR + identifiers, возвращает PEM + chain. Никогда не отдаёт приватник CA наружу.
- **ACME state**: отдельный SQLite в writable томе. См. [schema.md](schema.md).
- **CA store**: read-only mount существующего контекста secutor. Сервер только читает CA-ключ и сертификат при старте (или лениво при первом подписании) и держит в памяти.

## Поток выпуска (DNS-01)

1. Клиент `POST /newAccount` → создаётся аккаунт по JWK, выдаётся `kid`.
2. Клиент `POST /newOrder` с identifiers `[{type: "dns", value: "foo.lan"}]` → создаётся order + authz per identifier + challenge `dns-01` с token.
3. Клиент кладёт TXT `_acme-challenge.foo.lan` = `base64url(SHA256(token || "." || JWK_thumbprint))`.
4. Клиент `POST /chall/:id` → сервер ставит challenge в очередь, валидатор резолвит TXT через сконфигурированный DNS, сравнивает.
5. Все authz `valid` → order переходит в `ready`. Клиент `POST /finalize` с CSR.
6. Сервер проверяет, что SAN в CSR == identifiers в order, подписывает CA-ключом, кладёт сертификат, order → `valid`.
7. Клиент `GET /cert/:id` → PEM + chain.

## Поток выпуска (HTTP-01)

Идентично, но challenge-тип `http-01`: валидатор делает `GET http://<домен>/.well-known/acme-challenge/<token>` и проверяет тело. Применимо только если ACME-сервер сетево достижим до клиента на 80/tcp.

## Резолверы DNS

Конфиг: список upstream-резолверов с правилами по зонам.

```yaml
resolvers:
  - zones: ["lan", "vpn.local"]
    servers: ["10.0.0.53"]
  - zones: ["*"]
    servers: ["1.1.1.1", "8.8.8.8"]
```

Валидатор DNS-01 при проверке TXT идёт через резолвер, чей `zones` матчит. Это критично для внутренних доменов, которых нет в публичном DNS.

## Аутентификация и авторизация

- **Базовый режим (RFC 8555)**: любой клиент может создать аккаунт, challenge доказывает владение доменом.
- **Ограниченный режим (наше расширение, опционально)**: на аккаунт привязывается allow-list имён/зон. Заказ для имени вне allow-list отклоняется на `newOrder`. Allow-list задаётся CLI/админкой secutor.
- **Pre-authorized режим (опционально, не в первой версии)**: для CI/CD — выпуск через mTLS-аутентифицированный аккаунт без challenge. Это нестандарт, обычные ACME-клиенты не используют.

## Что не делаем в v1

- TLS-ALPN-01.
- EAB (External Account Binding) — для корпоративного onboarding'а, можно добавить позже.
- OCSP responder. Для отозванных — пока только CRL, генерируемая CLI.
- Multi-tenant. Один инстанс = один контекст secutor = один CA.

## Открытые вопросы

- Где жить отзывам: расширить существующий `audit.ts` или вести отдельный журнал в ACME-стейте? Склоняюсь к отдельному, чтобы CA-стор оставался read-only.
- Нужен ли встроенный acme-dns или достаточно RFC 2136 + плагины провайдеров? Решим после первой интеграции.

## Дополнительные подсистемы (v0.2+)

Этот раздел описывает, что добавилось поверх базовой ACME-картины выше.
Полные API-reference'ы — в отдельных доках; здесь только архитектурный
контекст и как куски соединяются.

### Admin API (mTLS)

Параллельный fastify-инстанс на отдельном порту (`config.admin.listen`).
На handshake принимает любой клиентский сертификат
(`requestCert:true, rejectUnauthorized:false`), а фактическую авторизацию
делает middleware:

1. Считает SHA-256(peer DER) и ищет в `config.admin.trust.fingerprints[]`.
2. Если не нашлось — пытается верифицировать цепочку peer'а против любого
   `config.admin.trust.cas[].caFile` и применяет `subjectMatch` фильтр.

Совпадение даёт роль `viewer` / `operator` / `owner` (выигрывает самая
высокая роль из всех сматчившихся правил). RBAC проверяется per-route.

Подсистемы внутри admin namespace:
- **Inventory + revoke** (operator+) — list/filter сертификаты, отзыв.
- **Accounts + ban** (owner для bann'а) — каскадный revoke всех валидных
  сертификатов аккаунта + cancel открытых ордеров в одной транзакции.
  Аудит-лог фиксирует ban-event id, который размечает каждую каскадную
  запись.
- **Stats** — агрегаты по статусам ордеров, success rate, top problem
  types (parsed `error_json.type`), top failing identifiers, временные
  корзины. Реализовано стандартными SQL-агрегатами + `json_extract`.
- **Audit log** — read с фильтрами `action`/`actor_id`/`target`/`since`.
- **Admin-issue** (operator+) — выпуск leaf в обход challenge'ей. Принимает
  CSR (сервер только подписывает) или самостоятельно генерит keypair и
  возвращает оба PEMa. Привязывается к синтетическому admin-аккаунту,
  идентифицируемому fingerprint'ом клиента — admin-issued сертификаты
  обособлены в листинге.

Подробнее: [admin-api.md](admin-api.md).

### CA bridge / rotation

Обёртка `CaStore` оборачивает canonical `CaMaterial` объект и держит
`staged` кандидата + `previous` для отката. Все читатели (routes, signer,
admin) держат живую ссылку на один и тот же `ca`-объект, который
`promote()` мутирует in-place через `Object.assign`. Это делает swap
наблюдаемым следующей же операцией подписи — без сложного atomic-handle
protocol'а.

Эндпоинты:

- `POST /admin/v1/ca/stage` (owner) — валидирует key↔cert (sign+verify
  nonce), chain до того же root, наличие ≥30 дней valid, отличность от
  активного. Хранит staged-кандидата в RAM.
- `GET /admin/v1/ca/staged` — read.
- `DELETE /admin/v1/ca/staged` (owner) — сбросить кандидата.
- `POST /admin/v1/ca/promote` (owner) — atomic swap; `previous`
  сохраняется на `rollbackWindowHours` (24 дефолт).
- `POST /admin/v1/ca/rollback` (owner) — восстановить `previous`.

Staged-материал живёт только в памяти. После рестарта оператор обязан
заново вызвать stage — это сознательный trade-off против риска хранения
полу-mutate'нных ключей на диске.

После promote `ReissueWorker` может перевыпустить все active leaf'ы под
новый ключ (см. ниже).

Подробнее: [ca-rotation.md](ca-rotation.md).

### Reissue worker

Background worker, который перевыпускает leaf-сертификаты под текущий
активный CA-ключ. Берёт SPKI/SANs/CN/validity из старого cert'а и
скармливает их в `issueLeaf` — клиентский приватник остаётся валидным
(public key не меняется), serial и подпись новые. В таблице `certificates`
обновляется `pem` + `serial_hex` той же row id.

Endpoints в admin namespace:

- `POST /admin/v1/jobs/reissue` (owner) — body `{scope, ratePerSec, ...}`.
  Scopes: `all-active`, `by-account`, `by-identifier-pattern`. Возвращает
  job row с total/done/failed.
- `GET /admin/v1/jobs/:id` — статус.
- `POST /admin/v1/jobs/:id/cancel` (owner).

Rate-limit между items — `1000 / ratePerSec` ms. Job state живёт в
`reissue_jobs` + `reissue_job_items`; переживает рестарт (worker
доберёт оставшиеся pending items на следующем тике).

### Server-managed DNS

Расширение `secutor.dnsPlacement = 'server-managed'` в `newOrder` говорит
хабу сам публиковать TXT-запись для DNS-01 challenge'а. На сервере
работает `DnsProviderRegistry` с zone-match dispatcher'ом
(longest-zone-wins).

Поток для server-managed order:
1. `newOrder` проверяет, что есть provider для каждого identifier'а —
   иначе сразу `rejectedIdentifier`.
2. Challenge сразу ставится `processing` (без ожидания клиентского
   `POST /chall/:id`).
3. Worker при первом тике делает `provider.place({name, value})` и пишет
   в таблицу `dns_placements` — для cleanup-on-restart.
4. Validator идёт обычным путём; на terminal outcome (`valid`/`invalid`)
   делается `cleanup` и placement помечается cleaned.

Поддерживаемые провайдеры: `rfc2136` (BIND nsupdate), `script` (внешний
shell hook), `memory` (для тестов). Новые добавляются в
`src/dns/providers.ts` + регистрируются в `dnsProviders.ts`.

При старте сервера `Worker.sweepStalePlacementsOnStartup()` собирает все
открытые placement'ы и cleanup'ит их — TXT-зона не накапливает мусор
после крэшей.

Подробнее: [server-managed-dns.md](server-managed-dns.md).

### ARI hint

`GET /renewalInfo/:id` — публичный, без mTLS. Возвращает
`{suggestedWindow: {start, end}}` согласно draft-ietf-acme-ari.
Heuristic: окно начинается в последней трети validity, заканчивается за
6 часов до not_after. После reissue, когда сертификат уже несёт новую
подпись, клиент при следующем GET увидит, что `start` уже в прошлом —
и пойдёт делать renew.
