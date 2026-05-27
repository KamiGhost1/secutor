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
