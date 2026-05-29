# Server-managed DNS-01

В стандартном RFC 8555 flow DNS-01 challenge'а **клиент** обязан положить
`TXT _acme-challenge.<домен>` сам — через RFC 2136 / cloud-provider CLI /
руками. Это нормально для CI-агентов, но плохо для оператора, который
хочет «выписать сертификат одной кнопкой».

Расширение `secutor.dnsPlacement: 'server-managed'` в `newOrder`
переворачивает поток: **хаб** публикует TXT-запись сам через
сконфигурированного провайдера, ждёт пропагации, валидирует, после
terminal outcome — убирает.

Стандартный flow (`client`-mode) продолжает работать без изменений.

## Конфигурация

```yaml
dnsProviders:
  - type: rfc2136
    zones: ["lan.vpn", "*.lan.vpn"]
    server: "10.0.0.53"
    keyFile: /etc/secutor-acme/tsig.key
    ttl: 30

  - type: script
    zones: ["dev.lan"]
    path: /usr/local/bin/dev-dns-update.sh

  - type: rfc2136                            # catch-all для прочих внутренних зон
    zones: ["*"]
    server: "10.0.0.53"
    keyFile: /etc/secutor-acme/tsig.key
```

Без блока `dnsProviders` server-managed-режим целиком выключен — попытка
создать `newOrder` с `secutor.dnsPlacement: 'server-managed'` сразу
получит `rejectedIdentifier`.

### Zone matching

Выигрывает **самое длинное** совпадение (longest-suffix). Правила:

- `"foo.lan"` — точное имя или `*.foo.lan`.
- `"*.foo.lan"` — то же, что `"foo.lan"` для матча (специфичность по
  длине суффикса).
- `"*"` — catch-all (specificity = 0).

Префикс `_acme-challenge.` снимается перед матчем — конфигурируйте по
видимому домену, не по `_acme-challenge.<домен>`.

## Типы провайдеров

### `rfc2136` (BIND nsupdate)

Требует:
- бинарника `nsupdate` (пакет `bind-tools` / `bind9-utils` / `dnsutils`);
- TSIG-ключа в BIND-формате:

```
key "acme-update." {
  algorithm hmac-sha256;
  secret "base64==";
};
```

Параметры: `server` (IP DNS-сервера), `zone` (берётся первая из `zones`),
`keyFile` (TSIG), `ttl` (default 60), `nsupdatePath` (override бинарника).

После `place` ждёт `min(ttl, 5)` сек на пропагацию на secondaries (для
zone-load'инг setup'ов это покрывает обычный SOA refresh).

При `cleanup` молча проглатывает `NXRRSET`/`NXDOMAIN`/`REFUSED` —
idempotency для случаев, когда запись уже была удалена (например, во
время cleanup-on-restart).

### `script`

Запускает внешний скрипт с env:

```
ACME_ACTION=place|cleanup
ACME_RECORD_NAME=_acme-challenge.foo.lan
ACME_RECORD_VALUE=...
```

Подходит для cloud-provider CLI (Cloudflare, Route53, DigitalOcean и т.п.)
без необходимости писать TypeScript-плагин.

### `memory` (только для тестов)

Хранит записи в `Map<name, Set<value>>` в RAM процесса. Не используйте
в production — после рестарта DNS-«зона» пуста.

## Поток с точки зрения клиента

```
client                                   hub                              DNS
  │                                       │
  ├── POST /new-order ───────────────────►│   identifiers + secutor.dnsPlacement=server-managed
  │   { secutor:{dnsPlacement:           │
  │     "server-managed"}}               │
  │                                       │  hub.dnsRegistry.hasProviderFor(id) → must be true
  │                                       │  insertOrder(dns_placement='server-managed')
  │                                       │  insertChallenge(dns-01) + queueChallenge(immediately)
  │◄── 201 + Location ────────────────────┤
  │
  │   (no chall POST needed — hub already queued it)
  │                                       │
  │                                       │  worker tick:
  │                                       │    provider.place(name=_acme-challenge.x, value=base64url(sha256(token+thumbprint)))
  │                                       │    insertPlacement → DB
  │                                       │  worker tick(+a bit later):
  │                                       │    validateDns01 (lookup TXT) → ok
  │                                       │    cleanupPlacementsFor(chall) → provider.cleanup
  │                                       │    chall→valid, authz→valid, order→ready
  │
  ├── POST /order/:id/finalize ──────────►│
  │   { csr }                             │  ... обычный signing ...
  │◄── 200 ────────────────────────────────┤
  │
  ├── GET /cert/:id ───────────────────────►│
  │◄── application/pem-certificate-chain ──┤
```

## Гарантии cleanup

TXT-запись убирается **во всех** terminal случаях:

- успешная валидация (`valid`) — больше не нужна.
- провал валидации (`invalid`) — после всех retry.
- истечение authz (`expired`).
- рестарт хаба — `Worker.sweepStalePlacementsOnStartup()` собирает все
  открытые placement'ы (`cleaned_at IS NULL`) и вызывает `cleanup` на
  соответствующих провайдерах. Провайдеры идемпотентны, повторный
  cleanup отсутствующей записи — это OK.

В таблице `dns_placements` хранится `(challenge_id, name, value,
provider_label, placed_at, cleaned_at)`. После cleanup'а `cleaned_at`
заполняется текущим временем — это и есть «journal» для recovery и
аудита.

## Аудит

В `audit_log` пишутся:

- `dns.place` — каждый успешный publish.
- `dns.cleanup` — каждый плановый cleanup (после terminal outcome'а
  challenge'а).
- `dns.cleanup.recovery` — cleanup при старте сервера (был оставлен с
  прошлой сессии).

## Параллельные ордера на тот же домен

Если два разных order'а одновременно идут на `svc.lan.vpn`, оба ждут
своих TXT-записей на `_acme-challenge.svc.lan.vpn`. Это OK: RFC 8555
позволяет multiple TXT values на одном имени (validator проверяет, что
**один из** TXT-ов совпадает с ожидаемым).

`rfc2136` provider использует `update add TXT` (а не `update replace`) —
существующие записи не затираются. Cleanup использует
`update delete <name> TXT "<value>"` — удаляет только конкретное
значение, оставляя прочие нетронутыми.

## Ограничения и known limitations

- Wildcard challenges (`*.foo.lan`) валидируются по TXT на
  `_acme-challenge.foo.lan` (без `*.`). Provider должен иметь TSIG-права
  на зону `foo.lan` — проверьте, что rule покрывает оба: `"foo.lan"` и
  `"*.foo.lan"` в одном `zones`.
- Server-managed DNS требует включённого `challenges.dns01: true`.
- `http-01` для server-managed не используется — хаб не клиент, не может
  обслуживать `.well-known/acme-challenge/` от чужого имени.
