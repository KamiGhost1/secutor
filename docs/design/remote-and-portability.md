# Дизайн: перенос ключей, удалённый ACME, авто-DNS и CA-bridge

Документ описывает дизайн шести связанных фич, которые превращают secutor из
локального TUI поверх SQLite в полноценный фронт-энд для распределённой PKI:

1. перенос ключевого материала между контекстами;
2. admin-API на acme-сервере (инвентаризация, статистика, отзыв, бан);
3. mTLS-подключение TUI к хабам (trust независим от ACME-цепочки, импорт
   ключа с диска, авто-поиск подходящих ключей в локальных контекстах);
4. удалённое управление сертификатами через TUI;
5. автоматическая публикация DNS-01 challenge-записей со стороны хаба;
6. CA-context bridge через хаб: проверка подписного ключа, ротация
   intermediate, фоновая джоба переподписания leaf-сертификатов.

Все фичи спроектированы так, чтобы существующие сценарии (полностью offline
secutor, существующий ACME RFC 8555 поток) не ломались — новое поведение
включается явными флагами/настройками.

## Оглавление

1. [Контекст и цели](#1-контекст-и-цели)
2. [Что есть сейчас (baseline)](#2-что-есть-сейчас-baseline)
3. [Сквозные понятия](#3-сквозные-понятия)
4. [Фича 1 — Перенос ключей между контекстами](#4-фича-1--перенос-ключей-между-контекстами)
5. [Фича 2 — Admin API на ACME-сервере](#5-фича-2--admin-api-на-acme-сервере)
6. [Фича 3 — mTLS-клиент secutor → хаб](#6-фича-3--mtls-клиент-secutor--хаб)
7. [Фича 4 — Удалённое управление сертификатами](#7-фича-4--удалённое-управление-сертификатами)
8. [Фича 5 — Авто-публикация DNS-записей при выписке](#8-фича-5--авто-публикация-dns-записей-при-выписке)
9. [Фича 6 — CA-context bridge через хаб](#9-фича-6--ca-context-bridge-через-хаб)
10. [Связность фич и порядок реализации](#10-связность-фич-и-порядок-реализации)
11. [Совместимость, миграции, безопасность](#11-совместимость-миграции-безопасность)
12. [Открытые вопросы](#12-открытые-вопросы)

---

## 1. Контекст и цели

Сегодня secutor — локальный инструмент: один пользователь, одна машина, один
SQLite-контекст. ACME-сервер — отдельный сервис, обслуживает RFC 8555 поверх
прочитанного один раз контекста secutor.

Цель набора фич — закрыть четыре практических разрыва:

1. **Портативность материала.** Сертификаты и ключи живут только внутри одного
   контекста. Их нельзя «передать» в другой контекст без ручного export-в-PEM +
   import. Это мешает разделять обязанности (root-context vs.
   intermediate-context, dev vs. prod) и переносить шифрованные подписные ключи
   между машинами без потери метаданных.
2. **Видимость и управление выпущенным.** Через ACME-сервер выпускаются десятки
   сертификатов. Узнать список, отозвать конкретный, посмотреть аудит — можно
   только зайдя по SSH на хаб и работая с `acme.db` напрямую. Admin API и
   удалённое управление из TUI снимают этот барьер.
3. **Удобство выпуска.** DNS-01 сейчас требует, чтобы клиент сам положил TXT.
   Авто-публикация со стороны secutor (когда secutor сам управляет DNS-зоной
   или имеет credentials) убирает ручной шаг и делает выписку «нажми Enter».
4. **Жизненный цикл CA-материала на хабе.** Сейчас «проверить, что хаб
   подписывает именно тем ключом», «заменить intermediate» и «переподписать
   все активные leaf'ы» — это руками на сервере. Хочется выполнить их из
   TUI поверх mTLS-канала, с атомарностью и аудитом.

Цели по UX:
- ни одна из новых фич не требует менять существующие данные на диске или
  переписывать формат контекста — только аддитивные таблицы и поля;
- secutor должен ясно показывать, когда он работает локально, а когда — с
  удалённым хабом (включая название хаба в шапке экрана);
- mTLS-подключение использует свободно выбираемый клиентский ключ —
  это может быть сертификат из локального контекста secutor, отдельный файл
  на диске, или ключ, импортированный в выделенный «hub keystore».
  Доверие на стороне хаба строится поверх fingerprint-allowlist'а и/или
  набора независимых admin-CA, не привязано к ACME-цепочке.

Non-goals (явно не в этом дизайне):
- multi-tenant на одном ACME-инстансе (по-прежнему 1 инстанс = 1 контекст);
- замена SQLite на распределённое хранилище;
- web-UI — всё новое только в TUI и CLI.

---

## 2. Что есть сейчас (baseline)

- **secutor (TUI):** контексты — SQLite-файлы в `~/.secutor/contexts/<name>/`,
  при шифровании — `store.enc` (AES-256-GCM, PBKDF2). Таблицы: `certificates`,
  `profiles`, `ssh_keys`. Импорт PEM/PKCS#12 умеет восстанавливать цепочку.
  Экспорт контекста — побайтное копирование файла.
- **ACME-сервер:** fastify + RFC 8555. БД `acme.db`: `accounts`, `orders`,
  `authorizations`, `challenges`, `nonces`, `certificates`, `audit_log`.
  Публичные эндпоинты сверх RFC: `GET /ca.pem`, `GET /chain.pem`,
  `GET /crl`, `GET /crl.pem`. Никакого API не-RFC для админских операций нет.
- **DNS-01:** клиент (`acme-server/src/client`) знает три хука — `manual`,
  `script`, `rfc2136`. На сервере публикации TXT нет — сервер только проверяет.
- **mTLS:** secutor умеет выпускать клиентские X.509-сертификаты. Никакой
  TLS/HTTP клиентской логики в TUI нет — все сетевые операции вынесены в
  отдельный `acme-server/src/client`, который сам запускается отдельно.

---

## 3. Сквозные понятия

Несколько терминов вводятся один раз и переиспользуются дальше:

- **Хаб (hub)** — машина, на которой развёрнут `secutor-acme`. У хаба есть
  стабильное имя (FQDN или ip), сертификат для своего HTTPS и (по новой фиче)
  admin-эндпоинт, защищённый mTLS.
- **Профиль хаба** — запись в реестре secutor (`~/.secutor/hubs.json`): имя,
  base URL, отпечаток серверного сертификата (для pinning) и ссылка на
  клиентский сертификат внутри какого-то контекста, которым TUI логинится по
  mTLS.
- **Карточка ключевого материала (key-bundle)** — портативное представление
  одной сущности (CA / leaf / SSH-ключ / P12) для переноса между контекстами:
  cert + private key (как есть, в т.ч. encrypted PKCS#8) + метаданные. Формат
  описан в фиче 1.
- **Admin-токен области (scope token)** — ACME-аккаунт с привязанным
  allow-list'ом + расширенным набором прав. Используется фичей 2 для
  выписки/отзыва/чтения из CLI и фичей 4 — из TUI поверх mTLS.

---

## 4. Фича 1 — Перенос ключей между контекстами

### 4.1. Что хотим

Возможность одной командой/одним экраном экспортировать выбранный CA, leaf
сертификат, SSH-ключ или P12-профиль из контекста A и импортировать его в
контекст B на той же или другой машине **с сохранением всех метаданных
secutor** (имя, comment, fingerprint, связь issuer→subject, encrypted-PKCS#8
ключ остаётся encrypted, пароли не вытаскиваются).

Это не замена нынешнему импорту PEM/P12 (тот сценарий — «принести материал
извне»). Здесь — «перенести изнутри в изнутри», без потери информации.

### 4.2. Формат key-bundle

Файл `.skb` (secutor key bundle), magic `SECUTOR_KB\x01`:

```
┌───────────────┬─────────────────────────────────────────────┐
│ 12 байт       │ magic 'SECUTOR_KB\x01' + 1-байт version=1   │
├───────────────┼─────────────────────────────────────────────┤
│ uint32 BE     │ длина manifest JSON                          │
├───────────────┼─────────────────────────────────────────────┤
│ N байт UTF-8  │ manifest JSON (схема ниже)                   │
├───────────────┼─────────────────────────────────────────────┤
│ остальное     │ payload blob (если он есть; для p12 — DER)   │
└───────────────┴─────────────────────────────────────────────┘
```

Manifest:

```json
{
  "v": 1,
  "kind": "ca" | "leaf" | "ssh" | "profile",
  "name": "intermediate-2026",
  "exportedAt": "2026-05-29T10:00:00Z",
  "exportedFrom": {
    "contextId": "<uuid из meta.json>",
    "secutorVersion": "1.1.3"
  },
  "fingerprint": "<sha256-hex>",
  "items": [
    {
      "role": "cert",                  // cert | key | parent | child | ssh-pub | ssh-priv | p12
      "encoding": "pem" | "der" | "openssh-v1" | "pkcs12",
      "encrypted": true | false,        // относится к private key
      "data": "<base64>"               // inline для текстовых форматов
    }
  ],
  "links": {                            // помощь для восстановления связей
    "issuerFingerprint": "<sha256-hex>",
    "subtreeFingerprints": ["..."]
  }
}
```

Правила:
- **Приватный ключ не расшифровывается при экспорте.** Если в контексте он
  лежит как encrypted PKCS#8 — таким же и попадёт в bundle. Пароль остаётся у
  пользователя, secutor его никогда не видел в открытом виде вне сессии.
- Sub-tree экспорт (CA + всё, что им подписано) — отдельный `kind: "subtree"`
  с массивом `items` в порядке от корня к листьям. Имена внутри bundle при
  импорте могут конфликтовать с существующими — резолвим как в 4.4.
- Bundle **может быть запароленным контейнером**: опционально оборачивается в
  age/AES-GCM-конверт (см. 4.5), magic тогда `SECUTOR_KB\x01E` (E — encrypted).
  Это полезно при передаче по неприватному каналу.

### 4.3. UX: новые экраны и кнопки TUI

- На экране деталей CA / leaf / SSH-ключа / P12 — новая горячая клавиша
  **`T`** (Transfer). Открывает меню:
  - *Export key bundle (.skb)* — выбрать файл назначения через `FileExplorer`,
    опционально включить sub-tree (только для CA), опционально зашифровать
    bundle паролем.
  - *Send to another context* — выбирает контекст-приёмник из списка, делает
    экспорт + импорт «в один клик» без промежуточного файла. Если контекст-
    приёмник зашифрован — попросит пароль приёмника.
- На экране списка контекстов (`ContextsScreen`) — новый пункт меню
  **«Import key bundle»**, который дёргает универсальный импортёр (4.4).
- В CLI (новые подкоманды):
  ```
  secutor keys export <name> [--context ctx] [--subtree] [--out file.skb] [--encrypt]
  secutor keys import <file.skb> [--context ctx] [--rename pattern]
  secutor keys transfer <name> --from ctxA --to ctxB [--rename pattern]
  ```

### 4.4. Импорт: дедупликация и конфликты имён

Импортёр обрабатывает bundle транзакционно:

1. Проверяет magic + version, при `encrypted` — спрашивает пароль и
   расшифровывает.
2. Для каждого `cert` в bundle считает SHA-256 DER и ищет дубликат в БД-приёмнике
   по `fingerprint`:
   - **Дубликат найден, ключ совпадает (по public key)** → апдейтим
     метаданные (имя, comment), приватник перезаписываем только если у
     приёмника он пустой или пользователь явно выбрал «overwrite».
   - **Дубликат найден, ключ другой** → ошибка `conflict: same fingerprint,
     different key`. Это аномалия, требует ручного разбора.
   - **Дубликата нет** → INSERT, имя — из manifest. При коллизии имени
     suffix-resolver добавляет `-2`, `-3`, ... или пользователь
     указывает шаблон через `--rename`.
3. Восстанавливает `issuer_id` через `issuerFingerprint`: ищет в приёмнике CA с
   таким же fingerprint. Если нет — ставит `NULL` и помечает запись для
   audit-finding `missing-issuer` (то же поведение, что и при обычном импорте).
4. Коммитит транзакцию. При любой ошибке — rollback.

UX по конфликтам — экран `ImportBundleScreen` показывает построчно: что новое,
что апдейт, что конфликт, и даёт `Y/N/Skip` по каждому пункту перед коммитом.

### 4.5. Шифрование bundle (опциональный конверт)

Когда передаём bundle через неприватный канал — Slack, e-mail, S3 — оборачиваем
во второй конверт:

- KDF: scrypt (N=2^17, r=8, p=1) — медленнее и устойчивее, чем PBKDF2 для
  «одноразового» bundle;
- симметрика: ChaCha20-Poly1305 (или AES-256-GCM, как в существующем
  контекст-шифровании), nonce — 24 байта, salt — 16 байт;
- header: `SECUTOR_KB\x01E` + версия + salt + nonce + длина ciphertext.

При расшифровке валидация AEAD-тега даёт чёткое «неверный пароль» вместо
мусора.

### 4.6. Что меняется в коде

| Что | Где | Тип изменения |
|---|---|---|
| Парсер/сериализатор bundle | новый модуль `src/transfer/keyBundle.ts` | new |
| CLI-команды `keys export/import/transfer` | `src/cli/commands.ts` | new |
| Экраны Transfer / ImportBundle | `src/screens/TransferScreen.tsx`, `ImportBundleScreen.tsx` | new |
| Хоткей `T` на деталях | `CertDetailsScreen.tsx`, `SshKeyDetailsScreen.tsx`, `ProfilesScreen.tsx` | edit |
| Универсальная функция «прорастить» bundle в репо | расширение `repos.ts` (новый метод `importBundle`) | edit |

Тестируем round-trip (`export → import` в чистый контекст даёт идентичную
БД-проекцию), конфликты имён, encrypted-конверт, sub-tree с глубиной 3.

---

## 5. Фича 2 — Admin API на ACME-сервере

### 5.1. Что хотим

Поверх существующего RFC 8555-эндпоинта добавить **отдельный admin namespace**
`/admin/v1/...` для:

- инвентаризации: список выпущенных сертификатов, фильтрация по статусу,
  account, identifier, времени, exp-окну;
- **агрегированной статистики** по ордерам (всего, по статусам, по причинам
  провала, по дням/часам, по аккаунтам, по идентификаторам) — см. 5.4;
- отзыва произвольного сертификата администратором (а не только владельцем
  аккаунта);
- **бана аккаунта-издателя с каскадным отзывом** всех выпущенных им
  валидных сертификатов одной операцией — см. 5.5;
- чтения аудит-лога (`audit_log`);
- управления allow-list'ом аккаунтов и pre-authorized режимом;
- получения метрик (счётчики выпущенных/отозванных/expired/expiring-soon).

Эти данные **уже лежат в `acme.db`** — задача только выставить их наружу
безопасно.

### 5.2. Авторизация admin namespace

Эндпоинты `/admin/v1/*` принимают **только mTLS-аутентифицированные
соединения** (см. фичу 3 на стороне клиента). Никакого Bearer-token, никакого
basic auth — только клиентский сертификат, подписанный CA того же контекста,
которым подписывает ACME.

На сервере:

- fastify слушает второй порт (например, `8444`) или тот же порт с
  `requestCert: true, rejectUnauthorized: true` для path-prefix `/admin/`;
- предпочтительно — отдельный listener, чтобы конфиг TLS (CA-trust для
  верификации клиентов) был изолирован от публичного ACME-эндпоинта;
- клиентский сертификат должен иметь EKU `clientAuth` и проходить проверку по
  CA-trust, в который положены явно admin CA bundle'ы;
- subject DN клиента маппится в **admin role** через конфиг
  (`config.admin.roles[].subjectMatch`): `viewer` / `operator` / `owner`;
- по умолчанию — `viewer`; маппинг работает «строгим матчем по subject
  contains».

```yaml
admin:
  listen: "0.0.0.0:8444"
  clientCaFile: /etc/secutor-acme/admin-ca.pem
  roles:
    - subjectMatch: "CN=ops-admin"
      role: owner
    - subjectMatch: "OU=NOC"
      role: operator
```

### 5.3. Эндпоинты (v1)

Все — JSON, с явным пагинированием (`?limit=&cursor=`), ответы стабильны
(snake_case, как в БД, чтобы не накручивать ещё один маппинг).

| Метод/путь                                | Роль       | Назначение |
|--|--|--|
| `GET /admin/v1/info`                       | viewer     | версия, fingerprint CA, статистика по таблицам |
| `GET /admin/v1/certificates`               | viewer     | список сертификатов; фильтры: `status`, `account_id`, `identifier`, `issued_after`, `expires_before`, `revoked` |
| `GET /admin/v1/certificates/:id`           | viewer     | полная запись (включая `pem`, `chain_pem`) |
| `POST /admin/v1/certificates/:id/revoke`   | operator   | админский отзыв; body `{reason: number}` |
| `GET /admin/v1/accounts`                   | viewer     | список аккаунтов с allow-list и `status` (`valid`/`deactivated`/`banned`) |
| `PATCH /admin/v1/accounts/:id`             | owner      | сменить статус (`valid`/`deactivated`), allow-list, contact |
| `POST /admin/v1/accounts/:id/ban`          | owner      | бан аккаунта + каскадный отзыв всех его сертификатов (см. 5.5) |
| `POST /admin/v1/accounts/:id/unban`        | owner      | снять бан (сертификаты НЕ восстанавливаются) |
| `GET /admin/v1/orders`                     | viewer     | список ордеров; фильтры: `status`, `account_id`, `since`, `until`, `identifier` |
| `GET /admin/v1/stats/orders`               | viewer     | агрегаты по ордерам (см. 5.4), фильтры по окну и группировке |
| `GET /admin/v1/stats/failures`             | viewer     | топ причин провала (по `orders.error_json.type`/`challenges.error_json.type`) |
| `GET /admin/v1/stats/issuance`             | viewer     | временной ряд выпусков/отзывов (для дашборда) |
| `GET /admin/v1/audit`                      | viewer     | пагинированный аудит-лог; фильтры по `action`, `actor_id`, `since` |
| `GET /admin/v1/metrics`                    | viewer     | Prometheus-формат (отдельно от JSON) |
| `GET /admin/v1/health`                     | viewer     | live/ready, доступность CA-материала в памяти |

Каждая операция в `operator`/`owner` пишет запись в `audit_log` с
`actor_type='admin'`, `actor_id` = SHA-256 fingerprint клиентского сертификата.

### 5.4. Статистика по ордерам

Все данные уже есть в `acme.db` (`orders`, `challenges`, `certificates`,
`audit_log`). Задача — выставить корректные агрегаты с фильтрами и
группировкой через `/admin/v1/stats/*`. Никаких новых хранилищ не вводим,
агрегируем SQL-запросами по индексам.

#### Что считаем

| Метрика | SQL-источник |
|---|---|
| всего ордеров за окно | `COUNT(*) FROM orders WHERE created_at BETWEEN ?` |
| по статусам (`pending`/`ready`/`processing`/`valid`/`invalid`/`expired`) | `GROUP BY status` |
| **успешно завершённых** (выпущен серт) | `COUNT(*) FROM orders WHERE status='valid'` |
| **провалившихся** | `COUNT(*) FROM orders WHERE status='invalid'` |
| **просроченных без финализации** (TTL истёк, не финализирован) | `COUNT(*) FROM orders WHERE expires_at < now() AND status NOT IN ('valid','invalid')` (нужен фон-воркер, отмечающий такие → `expired`) |
| провалы по типу challenge'а | join `orders → authorizations → challenges WHERE challenges.status='invalid'`, `GROUP BY challenges.type` |
| top-N причин провала | парс `challenges.error_json.type` (RFC 8555 problem.type) + `orders.error_json.type`, `GROUP BY type ORDER BY count DESC` |
| выпущено сертификатов за окно | `COUNT(*) FROM certificates WHERE issued_at BETWEEN ?` |
| отозвано за окно | `COUNT(*) FROM certificates WHERE revoked=1 AND revoked_at BETWEEN ?` |
| ratio failed / total | вычисляется в респонсе |
| по аккаунтам | `GROUP BY account_id` (с пагинацией) |
| по доменам/зонам | `GROUP BY identifier_value` или suffix-match по zones (post-aggregation в JS) |
| распределение по времени | bucket по часам/дням через `strftime('%Y-%m-%d', created_at)` |

#### Формат ответа

`GET /admin/v1/stats/orders?since=2026-05-01&until=2026-05-29&bucket=day&groupBy=status`:

```json
{
  "window": {"since": "2026-05-01T00:00:00Z", "until": "2026-05-29T00:00:00Z"},
  "total": 1843,
  "by_status": {
    "valid": 1701,
    "invalid": 88,
    "expired": 41,
    "pending": 12,
    "processing": 1
  },
  "success_rate": 0.923,
  "buckets": [
    {"ts": "2026-05-01", "total": 64, "valid": 60, "invalid": 3, "expired": 1},
    {"ts": "2026-05-02", "total": 71, "valid": 67, "invalid": 4, "expired": 0}
  ]
}
```

`GET /admin/v1/stats/failures?since=...`:

```json
{
  "total_invalid_orders": 88,
  "by_problem_type": [
    {"type": "urn:ietf:params:acme:error:dns",       "count": 41},
    {"type": "urn:ietf:params:acme:error:unauthorized", "count": 22},
    {"type": "urn:ietf:params:acme:error:badCSR",    "count": 18},
    {"type": "secutor:dnsProviderError",             "count": 7}
  ],
  "by_challenge_type": {"dns-01": 79, "http-01": 9},
  "top_failing_identifiers": [
    {"value": "broken.example.com", "count": 14},
    {"value": "no-such.lan.vpn",     "count": 9}
  ]
}
```

#### Аккуратность

- **`status='expired'`** в схеме сейчас нет (только `pending/ready/processing/valid/invalid`).
  Добавляем через миграцию (см. 5.6) и фон-воркер (раз в минуту), который
  переводит `pending`/`ready`/`processing` с `expires_at < now()` в `expired`.
  Без этого статистика «протухшие» врёт.
- **Индексы** на `orders(created_at)`, `orders(status, created_at)`,
  `certificates(issued_at)`, `certificates(revoked, revoked_at)` —
  обязательно, иначе на крупных хабах агрегаты будут лочить БД.
- **Окно по умолчанию** — 30 дней, чтобы случайный запрос без `since` не
  стащил всю историю.
- **Pagination для `groupBy=account`** — обязательная, лимит 200 строк.
- Все агрегаты должны быть **дёшево пересчитываемыми**: одиночные SQL без
  внешних JOIN'ов на >2 таблицы. Никакого пред-агрегированного materialized
  view в v1 — если упрёмся в производительность, добавим отдельную таблицу
  `stats_daily` с фоновой ролл-апом.

#### UX в TUI

В remote-режиме (фича 4) добавляем экран `RemoteStatsScreen`:

- шапка — выбор окна (1d / 7d / 30d / custom);
- три блока: «Orders» (donut по статусам + success rate), «Failures»
  (топ причин с ссылкой на конкретные order'ы), «Issuance over time»
  (текстовый sparkline по дням);
- кнопка `E` — экспорт текущей выборки в CSV в локальный файл.

### 5.5. Бан аккаунта-издателя с каскадным отзывом

#### Зачем

ACME-аккаунт может скомпрометировать ключ (украли account.key), или
сервис-«издатель» начал злоупотреблять (выписывает кучу несвязанных доменов,
ддосит challenge'и). В таком случае мало деактивировать аккаунт (RFC 8555
status `deactivated` — аккаунт больше не может создавать новые ордера); надо
ещё **отозвать всё, что он успел выпустить**, и пометить его так, чтобы
переактивация не возрождала старые сертификаты.

#### Модель

Добавляем третий статус аккаунта: `banned` (помимо RFC-стандартных `valid` и
`deactivated`). Семантика:

- `valid` — обычное состояние, может всё;
- `deactivated` — RFC 8555 §7.3.6: не может создавать новые order'ы и
  завершать существующие; выпущенные сертификаты остаются валидными;
- `banned` — наше расширение: то же, что `deactivated`, **плюс** все
  валидные (не отозванные, не истёкшие) сертификаты этого аккаунта помечены
  отозванными с `reason=privilegeWithdrawn` (RFC 5280 reasonCode 9).

Бан и unban — две раздельные операции. Unban **не** восстанавливает
отозванные сертификаты (отзыв необратим — попавший в CRL serial остаётся
там до истечения not_after, а relying parties могут его уже закэшировать).

#### Поток операции ban

`POST /admin/v1/accounts/:id/ban` body `{reason: number?, comment?: string}`:

1. mTLS + проверка роли `owner` (deny для viewer/operator).
2. Открыть транзакцию. Загрузить аккаунт; если уже `banned` → 409 conflict.
3. `UPDATE accounts SET status='banned', deactivated_at=now() WHERE id=?`.
4. Найти все валидные сертификаты:
   ```sql
   SELECT id, serial_hex FROM certificates
   WHERE account_id=? AND revoked=0 AND not_after > now();
   ```
5. Для каждого:
   - `UPDATE certificates SET revoked=1, revoked_at=now(),
     revocation_reason=?, revoked_by='admin:<fp>:ban' WHERE id=?` (reason
     по умолчанию — 9 `privilegeWithdrawn`, можно переопределить через body).
   - Запись в `audit_log` с `action='cert.revoke.cascade'`,
     `target=<cert.id>`, `details={account_id, ban_event_id, reason}`.
6. Отменить незавершённые ордера аккаунта:
   ```sql
   UPDATE orders SET status='invalid',
     error_json='{"type":"secutor:accountBanned",...}'
   WHERE account_id=? AND status IN ('pending','ready','processing');
   ```
7. Запись `action='account.ban'` в audit_log с числом затронутых сертификатов
   и ордеров.
8. Коммит транзакции.
9. Возврат:
   ```json
   {
     "account_id": "...",
     "previous_status": "valid",
     "banned_at": "2026-05-29T10:00:00Z",
     "revoked_certificates": 42,
     "cancelled_orders": 3,
     "reason": 9
   }
   ```

Транзакция критична: либо аккаунт забанен и всё отозвано, либо ничего.
SQLite WAL это позволяет, плюс отзыв — операция чисто на ACME-стейте, ничего
писать в CA-стор не надо (CRL генерируется при `GET /crl`).

#### CRL после бана

Текущий `buildCrl` уже выгребает все `revoked=1` сертификаты. После бана
следующий `GET /crl` / `/crl.pem` сразу включает каскадно отозванные. Чтобы
relying parties быстрее увидели изменения — рекомендуем понизить
`Cache-Control: max-age` на `/crl.pem` до 300 секунд (сейчас 3600).
Альтернатива — отдельный «push» через webhook (вне v1).

#### Защита от случайностей

- Бан — операция `owner`, не `operator`. UI запрашивает дополнительное
  подтверждение с превью «будет отозвано N сертификатов, в т.ч.: …» (первые
  10 серти, плюс кнопка «show all»).
- Конфиг сервера может включить **soft-ban**: `config.admin.banMode:
  'soft' | 'cascade'`. В `soft`-режиме операция только меняет статус
  аккаунта и отменяет открытые ордера, без отзыва сертификатов — это для
  случаев, когда нужно «выключить издателя» без блейст-радиуса по уже
  работающим сервисам. По умолчанию — `cascade`.
- Любой ban пишет в `audit_log` `actor_id` админа и в `details` — снапшот
  списка серти (только id + serial_hex, не PEM), чтобы можно было пост-фактум
  восстановить картинку без раскопок по timestamp'ам.

#### UX в TUI

На `RemoteAccountsScreen`:

- хоткей `B` (Ban) — открывает диалог с предпросмотром (что будет отозвано),
  выбором `reason`, обязательным полем `comment` (для audit-log) и yes/no;
- хоткей `U` (Unban) — простое подтверждение, в шапке предупреждение, что
  отозванные сертификаты не возвращаются;
- забаненные аккаунты подсвечены красным с иконкой, в списке сертификатов их
  серти показаны `revoked (cascade)`.

### 5.6. Изменения в `acme.db`

Миграция `0002_admin.sql`:

```sql
-- Account lifecycle
ALTER TABLE accounts ADD COLUMN deactivated_at TEXT;
-- расширяем допустимые значения status: 'valid' | 'deactivated' | 'revoked' | 'banned'
-- (CHECK снимаем, валидация на уровне приложения — sqlite не умеет ALTER CHECK)

-- Revocation provenance + cascade tag
ALTER TABLE certificates ADD COLUMN revoked_by TEXT;            -- 'account' | 'admin:<fp>' | 'admin:<fp>:ban'
ALTER TABLE certificates ADD COLUMN revoke_event_id TEXT;       -- id записи в audit_log, для группировки каскада

-- Order lifecycle: добавляем 'expired' (нужен фон-воркер)
-- (значения только в приложении)

-- Индексы под фильтры и агрегаты
CREATE INDEX IF NOT EXISTS idx_certs_issued      ON certificates(issued_at);
CREATE INDEX IF NOT EXISTS idx_certs_not_after   ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certs_revoked_at  ON certificates(revoked, revoked_at);
CREATE INDEX IF NOT EXISTS idx_certs_account     ON certificates(account_id, revoked, not_after);
CREATE INDEX IF NOT EXISTS idx_orders_created    ON orders(created_at);
CREATE INDEX IF NOT EXISTS idx_orders_status_t   ON orders(status, created_at);
CREATE INDEX IF NOT EXISTS idx_orders_account    ON orders(account_id, status);
CREATE INDEX IF NOT EXISTS idx_authz_status      ON authorizations(status);
CREATE INDEX IF NOT EXISTS idx_chall_status      ON challenges(status);
```

`audit_log` уже подходит, но добавляем индексы:

```sql
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_log(action, ts);
CREATE INDEX IF NOT EXISTS idx_audit_target      ON audit_log(target);
```

И фон-воркер `expireOrdersWorker` (раз в 60 секунд):

```sql
UPDATE orders SET status='expired'
WHERE status IN ('pending','ready','processing')
  AND expires_at < datetime('now');
```

Аналогично для `authorizations.status='expired'`.

### 5.7. Совместимость с RFC 8555

Admin namespace полностью отделён. Существующие ACME-клиенты (certbot,
acme.sh, cert-manager) ничего не замечают — для них всё, что не `/admin/`,
работает как раньше.

Расширение статуса аккаунта на `banned` — внутреннее. На уровне RFC-API
забаненный аккаунт ведёт себя как `deactivated`: попытка `newOrder` →
`unauthorized`. Само значение `banned` наружу через RFC-эндпоинты не торчит
(RFC-ответ `/acct/:id` возвращает `deactivated` для совместимости с
клиентами, не знающими нового статуса).

### 5.8. Что меняется в коде

| Что | Где | Тип |
|---|---|---|
| Отдельный fastify-инстанс с mTLS | `src/server/admin/index.ts` | new |
| Роуты admin v1 | `src/server/admin/routes.ts` | new |
| Stats-агрегаторы | `src/server/admin/stats.ts` | new |
| Ban / cascade revoke | `src/server/admin/accountBan.ts` | new |
| Запросы к репам | расширение `src/server/repos.ts` (list/filter/index методы + bulk revoke) | edit |
| Mapping subject → role | `src/server/admin/auth.ts` | new |
| Конфиг `admin:` (включая `banMode`) | `src/server/config.ts`, `config.example.yaml`, docker-compose example | edit |
| Фон-воркер `expireOrdersWorker` | `src/server/worker.ts` (расширение существующего) | edit |
| Тесты | `test/admin.ts`, `test/admin-stats.ts`, `test/admin-ban-cascade.ts` — RBAC, агрегаты, транзакционность каскада | new |

---

## 6. Фича 3 — mTLS-клиент secutor → хаб

### 6.1. Что хотим

В secutor TUI нужно подключаться к admin-API (фича 2), к будущему API
управления (фича 4) и к CA-bridge на хабе (фича 6) по клиентскому
сертификату.

Принципиально: **mTLS-сертификат админа не обязан быть подписан тем же CA,
которым хаб подписывает leaf-сертификаты**. Это два разных доверия:

- *ACME signing CA* — приватник, которым хаб выпускает leaf-сертификаты;
  с точки зрения admin-доступа абсолютно неважно, кто его подписал.
- *admin-trust* — настройка хаба «чьим клиентским сертификатам я доверяю
  для admin-API»; задаётся либо явным fingerprint-allow-list'ом, либо
  набором trusted CA (можно несколько, любых), либо комбинацией.

Это даёт оператору гибкость: можно админить хаб клиентским сертификатом из
полностью независимого PKI (или вообще одиночным self-signed), не подкидывая
ничего в основной CA-контекст.

### 6.2. Источники клиентской идентичности

Секьютор должен уметь брать клиентский сертификат + ключ из трёх источников
(в одном UI), плюс уметь подсказать, какие из локально доступных ключей
вообще годятся для конкретного хаба:

1. **Сертификат из контекста secutor** — выбор через picker по контексту и
   имени. Сегодняшний default, переиспользует репозитории и хоткей `T` из
   фичи 1.
2. **Файлы на диске** — пользователь указывает пути к `cert.pem` (или
   bundle) и `key.pem` (с паролем, если нужен). TUI читает их при каждом
   подключении (если не выбрано «import-into-keystore»), либо предлагает
   импортировать в выделенный «hub keystore» (см. 6.3).
3. **Auto-discover** — TUI сканирует все доступные локальные контексты и
   проверяет, какие сертификаты совпали бы с trust-policy хаба (см. 6.5);
   пользователь видит готовый список «эти ключи будут приняты».

Идентичность хранится в реестре хабов (6.3) как абстрактная «handle»,
которая знает, как достать `(cert_pem, key_pem)` к моменту установки
соединения, и при необходимости спросить пароль.

### 6.3. Реестр хабов

Новый файл `~/.secutor/hubs.json` (UI редактирует, формат стабилен):

```json
{
  "hubs": [
    {
      "id": "ops-hub-1",
      "name": "Prod hub (lan.vpn)",
      "baseUrl": "https://acme.lan.vpn:8444",
      "serverFingerprint": "sha256/abcd...ef",   // pin сертификата сервера
      "clientAuth": {
        "kind": "context",                       // context | file | keystore
        "context": "ops",
        "certName": "ops-admin-client",
        "rememberKeyPassword": false
      },
      "addedAt": "2026-05-29T10:00:00Z",
      "lastSeen": "2026-05-29T10:00:00Z"
    },
    {
      "id": "ops-hub-2",
      "name": "Stage hub",
      "baseUrl": "https://stage.lan.vpn:8444",
      "serverFingerprint": "sha256/...",
      "clientAuth": {
        "kind": "file",
        "certPath": "/home/op/.config/secutor-hubs/stage.crt",
        "keyPath":  "/home/op/.config/secutor-hubs/stage.key",
        "rememberKeyPassword": false
      }
    },
    {
      "id": "ops-hub-3",
      "name": "Bare-PKI hub",
      "baseUrl": "https://bare.lan:8444",
      "serverFingerprint": "sha256/...",
      "clientAuth": {
        "kind": "keystore",                      // импортированный в ~/.secutor/hubkeys/
        "keystoreEntry": "bare-admin"
      }
    }
  ]
}
```

Pinning серверного сертификата — обязателен. Сам серверный сертификат
тоже может быть из любого источника (self-signed, корпоративный CA,
Let's Encrypt) — для TUI имеет значение только pin'нутый отпечаток.

«Hub keystore» (`~/.secutor/hubkeys/<entry>/{cert.pem, key.pem.enc, meta.json}`)
— отдельное от контекстов хранилище для пары cert/key, специально
предназначенной для входа в хабы. Полезно, когда:

- ключ принципиально не должен жить в PKI-контексте secutor (например,
  выдан компанией через MDM);
- удобнее иметь «один файл-ключ под один хаб» без груза CA-метаданных.

Ключ внутри keystore шифруется тем же AES-256-GCM + PBKDF2, что и контексты;
пароль вводится на каждое подключение или хранится в памяти на сессию.

### 6.4. Trust-policy на стороне хаба (overrides 5.2)

Расширяем конфиг `admin:` на сервере, делая trust независимым от ACME
signing-цепочки и допускающим несколько источников одновременно:

```yaml
admin:
  listen: "0.0.0.0:8444"
  serverTls:
    certFile: /etc/secutor-acme/admin-server.crt
    keyFile:  /etc/secutor-acme/admin-server.key
  trust:
    # Разрешённые клиенты — ИЛИ-комбинация всех правил ниже.
    fingerprints:
      - sha256: "abcd...ef"
        role: owner
        label: "ops-admin (laptop)"
      - sha256: "1234...56"
        role: operator
        label: "ci-runner-1"
    cas:
      - caFile: /etc/secutor-acme/admin-ca.pem      # любой CA, не связанный с ACME
        subjectMatch: "OU=NOC"
        role: operator
      - caFile: /etc/secutor-acme/corp-mdm.pem
        subjectMatch: "OU=ops"
        role: viewer
  publishPolicy: true     # отдавать ли `/admin/v1/auth-policy` (см. 6.5)
```

Логика проверки:

1. TLS-handshake принимает любой клиентский сертификат (`requestCert: true,
   rejectUnauthorized: false`) — фактический контроль на уровне приложения.
2. Middleware сначала считает SHA-256 от `peerCertificate.raw`, ищет в
   `trust.fingerprints`. Совпало — выдаёт указанную роль.
3. Если не совпало — пытается верифицировать цепочку относительно каждого
   `trust.cas[].caFile`. Совпало + `subjectMatch` прошёл — выдаёт роль из
   правила.
4. Иначе — 401.

Существующая модель из 5.2 (один общий `clientCaFile`) — частный случай
`trust.cas: [{caFile, subjectMatch:'.*', role:'viewer'}]`. Чтобы не ломать
ранние деплои, оставляем поддержку старого поля как алиаса.

### 6.5. Picker и auto-discover ключей в TUI

#### Источники ввода

Новый экран `AddHubScreen` показывает три варианта source-selection:

| Опция | Что делает |
|---|---|
| **Use cert from context** | открывает picker, идентичный фиче 1 |
| **Use cert/key files on disk** | две строки FileExplorer'ом: cert + key, опциональный пароль; галка «Import into hub-keystore» — скопировать в `~/.secutor/hubkeys/<name>/` и удалить ссылки на абсолютные пути |
| **Auto-discover candidates** | сканирует и выводит список (см. ниже) |

#### Auto-discover

Хаб опционально публикует `GET /admin/v1/auth-policy` (без mTLS, только TLS;
включается флагом `publishPolicy: true`):

```json
{
  "fingerprints": [
    {"sha256": "abcd...ef", "label": "ops-admin (laptop)", "role": "owner"},
    {"sha256": "1234...56", "label": "ci-runner-1",        "role": "operator"}
  ],
  "cas": [
    {"caFingerprint": "9876...ba", "subjectPattern": "OU=NOC", "role": "operator"}
  ]
}
```

Дискавери в TUI работает так:

1. TUI делает GET `auth-policy`. Если хаб не отдаёт (`publishPolicy: false`
   или 404) — мягко падаем на «попробуй вручную».
2. Перебирает все клиентские сертификаты (`type='client'`) во всех контекстах
   secutor + все entries в hub-keystore.
3. Для каждого считает SHA-256 от DER, проверяет, есть ли совпадение в
   `policy.fingerprints` — это «точный матч», помечаем зелёным.
4. Для каждого, у которого не было точного матча, поднимает цепочку (через
   `issuer_id` в БД) до корня, считает fingerprint каждого CA, ищет
   совпадение в `policy.cas`. Совпало + subject leaf'а матчит
   `subjectPattern` — «по цепочке», помечаем жёлтым.
5. Показывает список: cert name + контекст + матч (зелёный/жёлтый) +
   обещанная роль. Пользователь выбирает запись — TUI прописывает её как
   `clientAuth` хаба и пытается подключиться для проверки.

Никаких «слепых пробных запросов» — мы знаем заранее, какие ключи подойдут.
Если `publishPolicy: false`, экран явно объясняет, что auto-discover
недоступен, и оставляет два других варианта.

#### Безопасность публикации auth-policy

Список fingerprint'ов — слабо чувствительная информация: знание SHA-256
чужого сертификата не даёт никаких прав, а сам сертификат можно увидеть
в любом TLS-handshake к тому, кто им пользуется. Тем не менее это раскрытие
поверхности доступа, поэтому `publishPolicy` по умолчанию `false`; в
закрытых LAN/VPN-сетапах включают руками.

### 6.6. TLS-настройка клиента

В Node.js это `https.Agent` с:

- `ca`: для проверки серверного сертификата принимаем **только** pin
  (см. ниже), системный trust-store при подключении не используется — это
  избавляет от вопроса «а откуда CA сервера?»;
- `cert` + `key`: достаются из выбранного источника (контекст / disk /
  keystore). Если key encrypted — TUI просит пароль (на каждое подключение
  по умолчанию; галка `rememberKeyPassword` — на время сессии в памяти,
  никогда на диск);
- `servername`: из baseUrl, для корректной SNI;
- проверка серверного fingerprint в `secureConnect`-коллбеке: вычисляем
  SHA-256 от `peerCertificate.raw`, сравниваем с `serverFingerprint`; не
  совпало — рвём соединение с понятной ошибкой `cert-pin-mismatch`.

Технически: `rejectUnauthorized: false` + ручная проверка fingerprint.
Цепочка не верифицируется, потому что pin сильнее цепочки.

### 6.7. UX

- На главном меню — пункт **«Hubs»** (рядом с «Contexts»). Открывает экран со
  списком хабов, кнопки **A**dd / **D**elete / **C**onnect / **R**echeck (повторно
  достучаться + обновить статус трасты).
- При добавлении хаба:
  1. ввести URL,
  2. выбрать источник клиентской идентичности (context / file / auto-discover),
  3. TUI делает первый запрос `GET /admin/v1/health` поверх mTLS,
  4. показывает fingerprint сервера и просит подтвердить (TOFU).
- При подключении — TUI меняет в шапке режим на `Hub: <name>` и переключает
  навигацию на «удалённый» вид (фича 4). По `Esc` из корня — выход обратно в
  локальный режим.
- Все операции в удалённом режиме маркируются цветом / иконкой в шапке, чтобы
  пользователь не перепутал отзыв сертификата на проде с локальной операцией.

### 6.8. Что меняется в коде

| Что | Где | Тип |
|---|---|---|
| Реестр хабов (расширенная схема `clientAuth.kind`) | `src/storage/hubStore.ts` | new |
| Hub-keystore (`~/.secutor/hubkeys/`) | `src/storage/hubKeystore.ts` | new |
| Identity-resolver (context / file / keystore → cert+key) | `src/net/clientIdentity.ts` | new |
| HTTP-клиент c mTLS + pinning | `src/net/hubClient.ts` | new |
| Экран Hubs + AddHub + AutoDiscover | `src/screens/HubsScreen.tsx`, `AddHubScreen.tsx`, `HubKeyPickerScreen.tsx` | new |
| Импорт client cert+key из файлов | расширение `ImportCertScreen.tsx` (флаг «как hub-key») | edit |
| Хоткеи и маршрутизация | `src/app.tsx`, `MainMenuScreen.tsx` | edit |
| Состояние «remote mode» | `src/state/AppContext.tsx` | edit |
| Хаб: миграция конфига `admin.trust.*` | `acme-server/src/server/config.ts`, `admin/auth.ts` | edit |
| Хаб: эндпоинт `auth-policy` | `acme-server/src/server/admin/policy.ts` | new |

### 6.9. Безопасность

- Пароль приватного ключа клиента никогда не уходит дальше памяти процесса.
- Pinning серверного сертификата делает несущественной валидность его
  цепочки — MITM с другим валидным сертификатом всё равно срежется по fp.
- На стороне хаба fingerprint-allowlist даёт точечное отзываемое доверие
  (удалить fp → клиент мгновенно теряет доступ), CA-trust — масштабируемое
  (выписал клиенту cert, подписанный admin-CA → автоматически имеет роль).
  Это две разные операционные модели, обе валидны.
- При смене серверного сертификата (легитимная ротация) — TUI явно требует
  пересохранения pin через тот же диалог TOFU, не «тихий апдейт».
- Hub-keystore шифруется тем же KDF/AEAD, что и контексты, не лежит открытым
  на диске.

---

## 7. Фича 4 — Удалённое управление сертификатами

### 7.1. Что хотим

В remote-режиме (после connect к хабу из фичи 3) TUI должен уметь делать
основные операции с сертификатами на хабе, не уходя в SSH:

- список сертификатов с фильтрацией (status, expiring soon, account, домен);
- детали сертификата (PEM, цепочка, audit-trail по серти);
- отзыв (с reasonCode);
- посмотреть аккаунты, allow-list, deactivate/**ban** аккаунт (с превью
  каскадного отзыва, см. 5.5);
- запустить выписку (создать order от имени admin-аккаунта — для CI-сценариев
  «инфра-команда выпустила leaf для сервиса вручную»);
- **посмотреть статистику** по ордерам (выпущено / провалено / просрочено,
  топ причин провалов) в формате дашборда — см. 5.4.

Технически это поверх admin API (фича 2).

### 7.2. Маппинг операций → API

| TUI-действие | API-вызов | Роль |
|---|---|---|
| Список сертификатов | `GET /admin/v1/certificates?...` | viewer |
| Детали | `GET /admin/v1/certificates/:id` | viewer |
| Скопировать PEM / chain | то же + локальная запись в файл/буфер | viewer |
| Отозвать | `POST /admin/v1/certificates/:id/revoke` | operator |
| Аккаунты | `GET /admin/v1/accounts` | viewer |
| Деактивировать аккаунт | `PATCH /admin/v1/accounts/:id` | owner |
| **Забанить аккаунт (с каскадом)** | `POST /admin/v1/accounts/:id/ban` | owner |
| **Снять бан** | `POST /admin/v1/accounts/:id/unban` | owner |
| Изменить allow-list | `PATCH /admin/v1/accounts/:id` | owner |
| Аудит | `GET /admin/v1/audit?...` | viewer |
| **Статистика по ордерам** | `GET /admin/v1/stats/orders?...` | viewer |
| **Топ причин провала** | `GET /admin/v1/stats/failures?...` | viewer |
| **Временной ряд выпусков** | `GET /admin/v1/stats/issuance?...` | viewer |
| Метрики дашборд | `GET /admin/v1/metrics` (parsed) | viewer |
| Выписать новый leaf admin'ом | новый `POST /admin/v1/certificates/issue` (см. 7.4) | operator |

### 7.3. UX

Экран `RemoteCertificatesScreen` визуально идентичен локальному
`CertificatesScreen`, чтобы пользователю не нужно было переучиваться. Шапка
показывает `Hub: <name>` и текущую роль admin'а. Хоткеи:

- `E` — экспортировать (PEM/chain в файл локально или в clipboard);
- `R` — отозвать (требует роль operator+, иначе кнопка серая с подсказкой);
- `V` — verify (локальная верификация с trust anchor = `ca.pem` хаба, кешируется);
- `/` — фильтр (тот же поиск, что в локальном экране);
- `D` — детали + аудит-трейл по сертификату.

Дополнительные экраны:

- `RemoteAuditScreen` (хоткей `A` из главного remote-меню) — stream
  аудит-лога с фильтром по action/actor/date range; в фильтрах есть готовый
  пресет «cascade revokes» (`action='cert.revoke.cascade'`).
- `RemoteStatsScreen` (хоткей `S`) — дашборд из 5.4: окно (1d/7d/30d/custom),
  donut по статусам ордеров, топ-причин провалов, sparkline выпусков по
  дням. Экспорт `E` пишет CSV локально.
- `RemoteAccountsScreen` — список аккаунтов; хоткей `B` (ban) показывает
  диалог с превью «будет отозвано N сертификатов: …», выбором `reason`
  (`privilegeWithdrawn` по умолчанию) и обязательным `comment` для
  audit-log. Хоткей `U` (unban) предупреждает, что отозванные серти не
  возвращаются.

### 7.4. Admin-issue: новый эндпоинт

Не RFC 8555 — собственный путь, нужен для админских выписок:

```
POST /admin/v1/certificates/issue
Content-Type: application/json
{
  "identifiers": [{"type": "dns", "value": "svc.lan.vpn"}],
  "csr": "<base64 DER>",                  // если есть CSR — используется
  "subject": { "commonName": "svc.lan.vpn" },  // если нет CSR — сервер сам генерит ключ
  "keyAlgorithm": "ecdsa-p256",                // нужен только при отсутствии CSR
  "notAfterDays": 90,
  "accountId": "<admin-account-id>" | null     // прицепить к admin-аккаунту
}
```

- Если передан `csr` — сервер не возвращает приватник.
- Если CSR не передан — генерит ключ на хабе, возвращает оба, сертификат
  записывается в `acme.db` под admin-аккаунтом. TUI пишет ключ в указанный
  пользователем локальный контекст через тот же механизм import bundle
  (фича 1).
- Эта операция **полностью пропускает challenge'и**: авторизация — mTLS, а
  не доказательство владения доменом. Хаб должен это явно логировать в
  `audit_log` с `action='cert.issue.admin'`.

### 7.5. Что меняется в коде

| Что | Где | Тип |
|---|---|---|
| Удалённый каталог экранов | `src/screens/remote/` (новая папка) | new |
| Дашборд статистики | `src/screens/remote/RemoteStatsScreen.tsx` | new |
| Экран аккаунтов с ban/unban | `src/screens/remote/RemoteAccountsScreen.tsx` | new |
| Repo-клиент к admin API (вкл. stats и ban) | `src/net/adminRepo.ts` (обёртка над hubClient) | new |
| Локальный verify против удалённого ca.pem | переиспользует `certs/verify.ts` | edit |
| Импорт «выписанного admin'ом» в локальный контекст | переиспользует `transfer/keyBundle.ts` (фича 1) | edit |
| Эндпоинт admin-issue на сервере | `src/server/admin/issue.ts` | new |

### 7.6. Авария-режим: что если хаб недоступен

Все операции — синхронные fetch. TUI показывает таймаут 10с, фолбэк-экран
«hub unreachable» с диагностикой (DNS, TCP, TLS, mTLS reject отдельно). Никаких
«eventual consistency» — пользователь либо видит ошибку, либо результат.

---

## 8. Фича 5 — Авто-публикация DNS-записей при выписке

### 8.1. Проблема и подход

Сегодня DNS-01 challenge требует, чтобы клиент сам положил TXT (либо через
manual hook, либо через `script`/`rfc2136`). Это нормально для CI-агента,
который знает, как обращаться с DNS, и плохо для оператора, который из TUI
запрашивает leaf — ему не должно требоваться знать, где живёт зона.

Подход — **разделение ответственности**:

1. **Клиент secutor** (или admin-issue хаба) при запросе сертификата может
   попросить сервер «возьми DNS на себя».
2. **Хаб ACME** имеет сконфигурированные «DNS provider'ы» (см. 8.3) и сам
   публикует/убирает TXT-записи, прежде чем триггерить challenge.

Это инверсия текущей логики: раньше TXT кладёт клиент, сервер только
валидирует; теперь — сервер может и положить, и проверить.

Сохраняем обе модели: классический клиент-кладёт-TXT работает без изменений,
авто-режим — опционально по флагу.

### 8.2. Расширение order: `dnsPlacement`

В `POST /new-order` (для admin-issue — в admin endpoint) клиент может передать
расширение:

```json
{
  "identifiers": [{"type": "dns", "value": "svc.lan.vpn"}],
  "secutor": {
    "dnsPlacement": "server-managed"   // "client" (по умолчанию) | "server-managed"
  }
}
```

Если `server-managed`:

- сервер при создании challenge сразу публикует TXT через сконфигурированный
  provider'a (см. 8.3);
- сервер сам ставит challenge в очередь валидации (вместо ожидания
  `POST /chall/:id` от клиента);
- по окончании жизни challenge'а (`valid`/`invalid`/`expired`) — сервер
  гарантированно делает cleanup TXT;
- если provider'а для зоны нет — order сразу `invalid` с проблемой
  `secutor:noDnsProvider` и понятным `detail`.

Существующее поле `secutor.dnsPlacement` — extension, не сломает клиентов,
которые его не знают.

### 8.3. Конфиг DNS-провайдеров хаба

Декларативный YAML, providers выбираются по zone-match (так же, как
существующие resolvers):

```yaml
dnsProviders:
  - zones: ["lan.vpn", "*.lan.vpn"]
    type: rfc2136
    server: "10.0.0.53"
    keyFile: /etc/secutor-acme/tsig.key
    ttl: 30

  - zones: ["dev.lan"]
    type: script
    path: /usr/local/bin/dev-dns-update.sh

  - zones: ["example.com", "*.example.com"]
    type: cloudflare                 # плагин, см. ниже
    apiToken: ${CF_API_TOKEN}
    zoneId: ${CF_ZONE_ID}
```

Типы провайдеров:

- **rfc2136** — переиспользуем существующий `rfc2136Hook` из
  `acme-server/src/client/dnsHooks.ts`, выносим его в общий `src/dns/` модуль,
  чтобы и сервер и клиент могли его использовать;
- **script** — то же самое, что клиентский scriptHook, только запускается на
  хабе с теми же env-переменными;
- **cloudflare** / **route53** / **gandi** — отдельные плагины-провайдеры в
  `acme-server/src/server/dns/providers/`. Один файл — один провайдер,
  имплементируют общий интерфейс `{place, cleanup, supportsZone}`.

### 8.4. Гарантии и обработка ошибок

- **Atomic place/check.** Если `place` упал — challenge сразу `invalid` с
  details из ошибки provider'а. Никаких pending TXT.
- **Cleanup гарантирован.** Хук cleanup вызывается:
  - при успешной валидации (TXT больше не нужен);
  - при failed-валидации;
  - при истечении authz (`expires_at`);
  - при рестарте сервера (recovery: при старте сервер находит challenge'и со
    статусом `processing` старше N минут и форсит cleanup).
  Cleanup идемпотентен: повторный delete несуществующей записи — успех.
- **TTL propagation.** Перед валидацией сервер ждёт min(provider.ttl, 30s)
  плюс делает несколько попыток DNS-резолва с экспоненциальным backoff (3
  попытки: 0, 2с, 8с). Это потому, что вторичные DNS могут отставать.
- **Параллельные order'ы на тот же домен.** TXT name (`_acme-challenge.X`)
  один на домен — если два разных order'а одновременно идут на `svc.lan.vpn`,
  TXT'ов должно быть несколько (multivalued TXT). RFC 2136 это умеет —
  `update add` дописывает, `update delete <name> <value>` удаляет только
  свой. Cleanup всегда указывает конкретный value, не name.

### 8.5. Аудит и observability

Каждое place/cleanup пишется в `audit_log` с
`action='dns.place'`/`'dns.cleanup'`, `target` = challenge id, `details` =
`{provider, zone, name, ttl}`. Метрика (`/admin/v1/metrics`) — счётчики успехов
и провалов по provider'у.

### 8.6. UX-привязка к TUI

В remote-режиме (фича 4) и при admin-issue:

- галка «server-managed DNS» в форме выписки;
- если в конфиге хаба нет provider'а для зоны, к которой относится
  identifier — галка серая, тултип объясняет почему;
- при выписке с `server-managed` TUI просто ждёт результата (5–60 секунд) и
  показывает прогресс по этапам: «published TXT» → «validating» → «issued».

### 8.7. Что меняется в коде

| Что | Где | Тип |
|---|---|---|
| Общий DNS-providers модуль | `acme-server/src/dns/` (вынос из client/dnsHooks.ts) | refactor + new |
| Подключение к серверу + dispatch по zones | `acme-server/src/server/dnsProviders.ts` | new |
| Расширение order и challenge worker | `routes.ts`, `worker.ts` | edit |
| Конфиг | `config.ts`, `config.example.yaml` | edit |
| TUI-форма | `src/screens/remote/RemoteIssueScreen.tsx` (новый) | new |
| Тесты | `test/dnsProvider-rfc2136.ts`, `test/dnsProvider-cleanup-on-restart.ts` | new |

---

## 9. Фича 6 — CA-context bridge через хаб

### 9.1. Что хотим

ACME-хаб держит в RAM расшифрованный приватник CA (intermediate, чаще
всего) — этого ему хватает, чтобы подписывать leaf'ы. Админу периодически
нужно сделать с этим CA-материалом то, что **сейчас требует SSH на сервер**:

1. **Проверить ключ, которым реально подписывает хаб** — действительно ли
   это тот intermediate, который оператор положил при деплое; не подменили
   ли его в результате supply-chain / rsync-fail / неправильного config
   reload'а. Сегодня для этого надо лезть на хаб руками.
2. **Обновить CA-материал** — заменить intermediate на новый (плановая
   ротация перед истечением, или после компрометации). Сегодня — `scp +
   docker compose restart`, без атомарности и без понятного аудита.
3. **Перевыпустить активные leaf-сертификаты** под новый CA — после
   ротации intermediate'а у уже выпущенных серти неправильный issuer/AKI,
   и они валидируются только до тех пор, пока relying parties держат старый
   intermediate в trust-store. Нужна джоба, которая в фоне переподпишет всё
   активное и оповестит ACME-клиентов, что пора забрать обновлённые
   сертификаты.

Это делается через хаб (а не через прямой доступ к контексту), потому что:

- расшифрованный материал уже есть в его памяти — не нужно второй раз
  открывать `store.enc`;
- хаб знает свою БД с историей выпусков — может построить полный список
  «что переподписать»;
- mTLS-канал из фичи 3 уже даёт безопасный путь админа к хабу — добавить
  ещё пути неправильно.

### 9.2. Эндпоинты CA-bridge (admin API)

| Метод/путь                                     | Роль     | Назначение |
|---|---|---|
| `GET  /admin/v1/ca`                            | viewer   | метаданные текущего CA: subject DN, alg, key params, SPKI fp, cert fp, not_before/not_after, chain summary |
| `POST /admin/v1/ca/verify`                     | operator | proof-of-possession: хаб подписывает переданный nonce приватником, TUI верифицирует подпись локально по ожидаемому публичному ключу (см. 9.3) |
| `GET  /admin/v1/ca/chain`                      | viewer   | full PEM-chain (issuer..root), для сверки с локальным контекстом |
| `POST /admin/v1/ca/stage`                      | owner    | загрузить новый CA-материал в staging (см. 9.4) |
| `POST /admin/v1/ca/promote`                    | owner    | сделать stage-материал активным (atomic swap) |
| `POST /admin/v1/ca/rollback`                   | owner    | вернуть предыдущий активный CA, если promote был < N часов назад |
| `GET  /admin/v1/ca/staged`                     | viewer   | информация о staged-кандидате (если есть) |
| `POST /admin/v1/jobs/reissue`                  | owner    | поставить джобу переподписания (см. 9.5) |
| `GET  /admin/v1/jobs/:id`                      | viewer   | статус и прогресс джобы |
| `POST /admin/v1/jobs/:id/cancel`               | owner    | отменить джобу (только до начала записи в БД) |

### 9.3. Проверка ключа

«Проверить ключ» — это не «прочитать публичную часть» (это знает любой
наблюдатель), а **убедиться, что приватник у хаба тот самый, что
ожидается**. Двухшаговый протокол:

1. TUI знает ожидаемый CA (либо из локально лежащего экспорта `cert.pem`,
   либо из локального secutor-контекста, в котором хранится тот же
   intermediate). Из него извлекает публичный ключ.
2. TUI генерит 32 случайных байта `nonce`, кидает `POST /admin/v1/ca/verify
   {nonce}`. Хаб подписывает `SHA-256("secutor-ca-verify-v1" || nonce)`
   приватником CA (без вмешательства в обычный signing-поток) и возвращает
   `{signature, alg, certPem}`.
3. TUI:
   - проверяет `certPem` совпадает с ожидаемым по fingerprint;
   - проверяет подпись `signature` против ожидаемого публичного ключа.
4. Совпало — зелёная галка «ключ соответствует». Не совпало — красный с
   подсказкой возможных причин (контекст не тот / ротация была не закрыта
   promote'ом / staging-материал ещё не активирован).

Префикс `"secutor-ca-verify-v1"` исключает риск, что подпись из
verify-протокола случайно совпадёт с чем-то осмысленным (CSR, OCSP,
TBSCertificate) и будет переиспользована атакующим.

Для ECDSA/Ed25519 — стандартная схема (`crypto.sign(hash, msg, key)`). Для
RSA — RSASSA-PSS с SHA-256.

### 9.4. Обновление CA-материала (staging → promote)

Атомарный двухфазный путь:

#### Фаза 1. Stage

`POST /admin/v1/ca/stage` принимает мультипарт:

```
fields:
  cert:    PEM нового intermediate
  key:     зашифрованный PKCS#8 нового intermediate (encrypted by secutor — same envelope as context's)
  chain:   PEM остатка цепочки (от родителя нового intermediate до root)
  keyPassword: ...      (если ключ encrypted; передаётся отдельным полем, читается из памяти и обнуляется)
```

Хаб:

1. Расшифровывает `key` переданным password'ом — проверка «ключ открывается».
2. Парсит `cert`, проверяет, что `subjectPublicKeyInfo` соответствует
   расшифрованному private key (sign+verify тестового nonce).
3. Проверяет, что `cert.publicKey != current.publicKey` (иначе зачем
   ротация) и что `cert.notAfter > now() + 30d` (минимальное окно).
4. Проверяет цепочку до того же root, что и текущий CA (`chain` собирается
   и валидируется через openssl-equivalent). По-другому конфиг переключать
   нельзя — иначе у клиентов сломается trust anchor (см. ca-lifecycle.md
   про root).
5. Кладёт staged-материал в **отдельный mount** на диске
   (`/var/lib/secutor-acme/staged/`) — не в БД, чтобы при крашe он не
   попал в активный путь подписывания.
6. Возвращает `{stagedFingerprint, notAfter, keyAlg}`.

Активный signing-pipeline на этом этапе **не трогается** — хаб продолжает
подписывать старым CA. Staging можно снять (`DELETE /admin/v1/ca/staged`)
без последствий.

#### Фаза 2. Promote

`POST /admin/v1/ca/promote` — атомарная замена «active CA в памяти и на
диске»:

1. Под локом подписания: новый key/cert загружается в `CaMaterial` в RAM
   (та же структура, что заполняется в `contextLoader.ts` при старте).
2. Старый материал сохраняется в `previous` (для rollback).
3. На диск — переименование `staged/` → `active/` атомарным `rename(2)`.
4. Запись в `audit_log` (`action='ca.promote'`, details = старые/новые
   fingerprints).
5. Любой следующий `finalize` сразу использует новый ключ.

Все pending `processing` ордера, которые не успели подписать на старом
ключе, либо честно проходят как обычно (если CSR ещё не пришёл) — они
получат новый issuer. Это семантически корректно, потому что order пока
без выпущенного серти, и клиент ещё ничего не видел.

#### Rollback

`POST /admin/v1/ca/rollback` доступен **N часов** (config-параметр,
дефолт 24) после promote. После этого окна хаб удаляет `previous/` —
дальше rollback только через явный новый stage+promote старого материала.

### 9.5. Джоба переподписания

После promote часть relying parties начнёт нарываться на цепочку с уже
неизвестным им (старым) intermediate в trust-store, у которого ещё валидный
serial — поэтому хочется заменить leaf'ы на подписанные новым intermediate.

#### Постановка джобы

`POST /admin/v1/jobs/reissue`:

```json
{
  "scope": "all-active" | "by-account" | "by-identifier-pattern",
  "accountIds": ["..."],            // для by-account
  "identifierPattern": "*.lan.vpn", // для by-identifier-pattern
  "strategy": "resign" | "reissue",
  "notifyClients": true,
  "rateLimitPerSec": 10
}
```

Стратегии:

- **resign** — берём существующий leaf cert, копируем subject/SANs/SPKI/
  validity, генерируем новую подпись новым CA-ключом (та же логика, что
  `resignCertificateCore` в secutor `src/certs/core.ts`). Приватник клиента
  не меняется. Это работает, когда у нас в `acme.db` лежит весь PEM
  оригинала — а он там лежит.
- **reissue** — выпускаем полностью новый сертификат с новым serial и теми
  же identifiers. Используется, когда хочется ротировать и leaf-ключи
  тоже, **но** новый leaf-ключ должен сгенерить сам клиент (через
  обычный ACME order). Сервер сам ключи клиентам не генерирует — поэтому
  reissue-стратегия на самом деле сводится к «помечаем все matching
  серти как «pending reissue», ACME-клиент при следующем запросе видит
  hint через RFC 8555 ARI (`/renewalInfo`, draft) и идёт делать новый
  order». См. 9.6.

Для скоупа `all-active` дефолт — `resign`, для остальных оператор выбирает
явно.

#### Исполнение

- Джоба — фон-воркер на хабе, состояние пишется в новую таблицу
  `reissue_jobs` (id, scope, params_json, status, total, done, failed,
  started_at, finished_at) + `reissue_job_items` (job_id, cert_id,
  status, error).
- Rate limit обязателен — переподписание тысяч leaf'ов за секунду затушит
  любую I/O-производительность. Дефолт 10/сек, конфигурируется.
- Каждое успешное resign пишет новый `pem` в `certificates` (`updated_at`
  заполняется) и кладёт запись `action='cert.resign'` в `audit_log` с
  `details.job_id`.
- При ошибке отдельного cert — джоба продолжает, item уходит в `failed`,
  пользователь видит частичный успех в финальном статусе.

#### Прогресс в TUI

`GET /admin/v1/jobs/:id` отдаёт live-статус. Экран
`RemoteCaRotationScreen` показывает progressbar (`done/total/failed`),
ETA, и log-tail последних 20 событий. Джоба переживает рестарт хаба
(`reissue_jobs.status='running' AND started_at < now() - heartbeat` →
помечается `interrupted`, оператор решает, продолжать или отменять).

### 9.6. Уведомление ACME-клиентов

После resign'а leaf'а его serial меняется (новая подпись — новый serial),
поэтому клиент, у которого ещё лежит старый файл, должен забрать новый.
Два механизма:

- **RFC 8555 ARI extension** (`/renewalInfo` — draft-ietf-acme-ari):
  для каждого выпущенного серти отдаём `suggestedWindow.start = now()`,
  что значит «начни перевыпускать прямо сейчас». Совместимые клиенты
  (cert-manager поддерживает, certbot — в roadmap) тут же пойдут в reissue.
- **Pre-signed URL** на скачивание свежего PEM: на старый `GET /cert/:id`
  отдавать **новый** `pem` + `chain_pem` (так как у нас тот же id), но
  с новой подписью. Существующие клиенты, которые периодически дергают
  `/cert/:id` (cert-manager делает это перед renew, чтобы убедиться) —
  заметят. Это уже работает в текущем коде без изменений, потому что
  `GET /cert/:id` всегда возвращает текущий PEM из БД.

Для `notifyClients: true` ещё пишем `audit_log
action='cert.reissue.hint'`, чтобы оператор видел, когда сервер начал
толкать ARI-hint'ы.

### 9.7. UX в TUI

Новый экран `RemoteCaScreen` (в remote-режиме, хоткей `C`):

- блок «Active CA» — subject, alg, fingerprint cert, fingerprint SPKI,
  not_after с цветом по 90d/30d/7d-окну, кнопка **V** (verify) — запускает
  proof-of-possession (9.3) с предложением выбрать ожидаемый материал из
  локального контекста или из файла;
- блок «Staged CA» — пусто или метаданные staged-кандидата с кнопками
  **P** (promote) и **D** (discard);
- блок «Recent rotations» — последние 5 записей `ca.promote` из audit;
- кнопка **R** (rotate) — открывает `RemoteCaRotateScreen`:
  1. выбор источника нового материала — локальный контекст secutor (тот
     же picker, что в фиче 1) или внешний `.skb` key bundle;
  2. подтверждение fp + параметров;
  3. stage → подтверждение → promote → опциональная постановка
     re-issue job (галка «kick off resign of all active leaves»).

Все деструктивные шаги (promote, rollback, reissue all-active) —
double-confirm с напечатанным fingerprint'ом, чтобы исключить случайные
клики.

### 9.8. Что меняется в коде

| Что | Где | Тип |
|---|---|---|
| Эндпоинты CA-bridge | `acme-server/src/server/admin/ca.ts` | new |
| Staging-store на диске | `acme-server/src/server/caStaging.ts` | new |
| Atomic swap в `CaMaterial` | `acme-server/src/server/contextLoader.ts` | edit (поддержка hot-replace) |
| Таблицы `reissue_jobs` + `reissue_job_items` | миграция `0004_reissue_jobs.sql` | new |
| Воркер reissue | `acme-server/src/server/reissueWorker.ts` | new |
| Resign-логика | вынесем общую часть из secutor `src/certs/core.ts` → переиспользуем на хабе | refactor |
| TUI: экраны CaScreen / CaRotateScreen / JobProgressScreen | `src/screens/remote/RemoteCa*.tsx` | new |
| TUI: proof-of-possession клиент | `src/net/caBridge.ts` | new |
| Тесты | `test/admin-ca-verify.ts`, `test/admin-ca-rotate.ts`, `test/reissue-job.ts` | new |

### 9.9. Безопасность

- Promote — операция роли `owner`, не `operator`. Один неверный promote
  заменит signing-ключ для всей инфраструктуры.
- Stage кладёт ключ на диск хаба зашифрованным (тем же envelope, что и в
  `store.enc`). Расшифровка происходит только в RAM, при promote.
- Password нового ключа передаётся в `stage` отдельным полем; TUI спрашивает
  его непосредственно перед отправкой и не сохраняет.
- Verify (9.3) не подписывает ничего, что может быть подменено на CSR
  или TBS — благодаря префиксу `"secutor-ca-verify-v1"`.
- Rollback-окно ограничено (`config.ca.rollbackWindowHours`), потом
  предыдущий ключ удаляется shred'ом с диска хаба.
- Re-issue job ограничен rate-limit'ом и логирует каждое действие. Откат
  невозможен (resign — действие необратимое), поэтому подтверждение
  обязательное.

---

## 10. Связность фич и порядок реализации

Зависимости:

```
                            ┌──────────────────────┐
                            │ 1. Key bundle        │◄──────────────────────┐
                            └──────────┬───────────┘                       │
                                       │ переиспользуется (импорт          │
                                       │ нового CA, импорт client key)     │
                                       ▼                                   │
                            ┌──────────────────────┐                       │
                            │ 4. Remote management │─────────┐             │
                            └──────────┬───────────┘         │             │
                                       │ требует              │             │
                                       ▼                      │             │
        ┌─────────────────► ┌──────────────────────┐         │             │
        │                   │ 3. mTLS hub client   │         │             │
        │                   └──────────┬───────────┘         │             │
        │                              │ обращается к         │             │
        │                              ▼                      ▼             │
        │                   ┌──────────────────────┐ ┌──────────────────────┐
        │                   │ 2. Admin API         │ │ 5. Auto-DNS provider │─┘
        │                   └──────────┬───────────┘ └──────────────────────┘
        │                              │ расширяется
        │                              ▼
        │                   ┌──────────────────────┐
        └──── auto-discover │ 6. CA-context bridge │
              ключей по     │  (verify / rotate /  │
              auth-policy   │   reissue job)       │
                            └──────────────────────┘
```

Предлагаемый порядок (от наиболее независимого):

1. **Фича 1** (key bundle) — полностью локальная, не трогает сервер.
2. **Фича 2** (admin API) — на сервере; пока без клиента, проверяется curl'ом
   с временным client cert.
3. **Фича 3** (mTLS hub client) — клиент в TUI; первая полезная остановка
   после неё — read-only удалённый просмотр через admin API. Trust-policy и
   auth-policy publishing разрабатываются вместе с этой фичей.
4. **Фича 4** (remote management экраны) — UX поверх 2+3.
5. **Фича 5** (auto DNS) — отдельная плоскость, можно делать параллельно с 4,
   когда 2 уже есть.
6. **Фича 6** (CA-context bridge) — самая глубокая, требует 2+3, и
   переиспользует bundle-формат фичи 1 для импорта нового intermediate.
   Делается последней; внутри тоже фазируется: сначала `verify`, потом
   `stage/promote`, потом re-issue job.

Каждую фичу можно мерджить независимо, скрывать за фичефлагом до полной
готовности связки.

---

## 11. Совместимость, миграции, безопасность

### Совместимость

- Контексты secutor — никаких изменений схемы для фичи 1: bundle — это
  файл-конверт, БД-структура та же.
- `acme.db` — три минорные миграции (`0002_admin.sql`,
  `0003_dns_providers.sql`, `0004_reissue_jobs.sql`), все аддитивные (только
  `ALTER TABLE ... ADD COLUMN` и `CREATE TABLE IF NOT EXISTS`).
  Откатываются за счёт того, что новые колонки nullable и новые таблицы
  опциональны.
- ACME RFC 8555 — никаких ломающих изменений. Расширение `secutor.dnsPlacement`
  игнорируется незнающими клиентами. ARI-hint (фича 6) — отдельный
  опциональный эндпоинт `/renewalInfo`, не влияет на основной flow.
- Конфиг хаба: поле `admin.clientCaFile` из ранних версий продолжает
  работать как алиас `admin.trust.cas[0]` (фича 3); явная миграция не
  требуется.

### Миграции

- В secutor миграции версионируются файлом `meta.json` контекста (поле
  `schemaVersion`), миграция bundle-format будет вшита в код парсера (поле
  `v` в manifest).
- В acme-server — обычный SQL-migrate в `db.ts` при старте.
- Hub-keystore (`~/.secutor/hubkeys/`) и реестр хабов (`hubs.json`) —
  новые на пустом месте, миграции не нужны.

### Безопасность

- **Secrets никогда не покидают свой слой:** пароли контекстов и приватные
  ключи не сериализуются в bundle расшифрованными; пароли mTLS-ключей не
  кешируются на диске; admin actions всегда фиксируются с fingerprint
  клиента.
- **Pin серверного сертификата** обязательный — без него mTLS-клиент
  отказывается работать. Это защита от компрометации публичного PKI на
  хабе.
- **Roles минимальны:** viewer не может ничего изменить, operator не может
  менять структуру (allow-list, статусы аккаунтов), только сертификаты и
  отзывы.
- **DNS auto-provider** — обладает мощным правом писать в DNS-зону, поэтому
  конфигурируется только статически в YAML, не через API. Никакого
  динамического «добавьте мне нового провайдера через REST».
- **Audit-log админских действий должен быть append-only** — добавляем
  pragma-проверку в миграциях или ставим триггер `BEFORE UPDATE/DELETE` на
  `audit_log` с rollback.

---

## 12. Открытые вопросы

1. **Формат encrypted bundle (фича 1):** scrypt vs argon2id. scrypt дешевле в
   зависимостях (есть в node:crypto), argon2id сильнее на ASIC. Если согласны
   на native-зависимость — argon2id предпочтительнее.
2. **Порт admin API (фича 2):** отдельный listener (`:8444`) или path-prefix
   на общем (`:8443/admin`)? Отдельный — чище для TLS-конфига, но требует
   дополнительной публикации в docker/compose. Решим, когда будем писать
   `Dockerfile`-update.
3. **TOFU UX (фича 3):** должны ли мы при первом подключении показывать
   fingerprint в hex + слова (mnemonic, как WireGuard PSK) для удобства
   сверки голосом? Это микро-фича, но реально помогает на проде.
4. **Admin-issue в обход challenge (фича 4.7.4):** правильно ли это в принципе?
   Альтернатива — admin создаёт **pre-authorized** authz, клиент завершает
   нормальный flow. Чище с точки зрения RFC, но требует больше шагов на
   клиенте. Склоняюсь к admin-issue, как самостоятельной операции, но с
   явным аудитом и роль `operator`.
5. **Auto-DNS для wildcard'ов (фича 5):** при wildcard challenge сервер
   публикует TXT на `_acme-challenge.<base>`. Это корректно для RFC 8555,
   но провайдер должен иметь права на зону `<base>`, не на сам wildcard.
   Конфиг должен явно матчить и `*.foo` и `foo` в одной записи zones.
6. **Откат фичи 5:** что делать, если хаб упал в момент `place`, до записи
   в БД? Сейчас предложен recovery на старте сервера. Альтернатива — outbox-
   pattern (запись «нужно cleanup» в БД до place). Outbox чище, но усложняет
   путь. Решить после прототипа.
7. **Pre-aggregation для статистики (фича 5.4):** если хаб обслуживает 10k+
   ордеров в день, on-the-fly `GROUP BY` начнёт тормозить. Стоит ли сразу
   класть отдельную таблицу `stats_daily` с фоновой ролл-апом, или дождаться
   реального сигнала «медленно»? Склоняюсь ко второму — преждевременная
   оптимизация.
8. **Bulk-revoke при бане (фича 5.5):** при сотнях валидных сертификатов
   на одном аккаунте ban-транзакция может занять заметное время. Стоит ли
   ограничить размер каскада (например, отбивать `ban` при >1000 серти с
   рекомендацией «отзови вручную пачкой»), или просто давать длинный таймаут
   и прогресс-бар в TUI? Текущая ставка — прогресс-бар, без жёсткого лимита.
9. **«Тихий» статус `banned` в RFC-ответах (фича 5.7):** мы скрываем `banned`
   за `deactivated` для RFC-клиентов. Альтернатива — отдавать честный
   `banned` и смотреть, ломаются ли клиенты. По духу RFC — лучше отдавать
   честно (это всё-таки строка, а не код), но я бы пошёл с консервативным
   вариантом до явных багов в реальных клиентах.
10. **Публикация `/admin/v1/auth-policy` (фича 3.5):** включаем дефолтом или
    оставляем opt-in? Польза очевидна (auto-discover «работает из коробки»),
    риск — fingerprint'ы видны без аутентификации. Для LAN-сетапов риск
    низкий, для публично выставленных хабов — выше. Текущая ставка —
    opt-in.
11. **Альтернатива auto-discover без публикации (фича 3.5):** вместо
    publish'а ключей хаба можно дать TUI «пробный» эндпоинт `POST
    /admin/v1/auth-probe`, который без побочных эффектов отвечает «эта
    идентичность подходит / не подходит / роль такая». Тогда TUI не видит
    полный список ключей хаба, но узнаёт результат проверки своих. Чище с
    точки зрения information disclosure, требует больше round-trip'ов.
12. **Stage-конверт нового CA (фича 6.4):** оборачивать ли его в
    `.skb`-формат (фича 1) или использовать многосоставный POST с теми же
    полями? `.skb` даёт единый файл, который удобно проносить через UI и
    автоматизацию; multipart — проще для cURL-сценариев. Скорее всего
    поддержим оба, единый — основной.
13. **Hot-replace `CaMaterial` под нагрузкой (фича 6.4):** atomic swap под
    локом подписи нормально работает, если signing-операции короткие
    (миллисекунды). Если в какой-то момент мы добавим длинные операции
    (например, RSA-4096 + CRL c тысячами записей за раз) — лок может
    задержать promote. Возможный фикс — двойная буферизация (новый
    `CaMaterial` обслуживает только новые запросы, старый дорабатывает
    in-flight). Не нужно в v1, держим в уме.
14. **Reissue для wildcard'ов и SAN-множеств (фича 6.5):** resign копирует
    SAN'ы 1:1 из исходного `pem`. Что если SAN изначально содержал
    идентификаторы, которые сегодня запрещены allow-list'ом аккаунта?
    resign их сохранит (это «продление того же сертификата другой подписью»,
    а не выпуск нового). Корректное поведение, но стоит явно задокументировать.
15. **ARI-hint и backwards-совместимость (фича 6.6):** ARI — draft, не
    финализированный RFC. Отдельные клиенты могут падать на неожиданном
    эндпоинте. Включаем за конфиг-флагом `admin.ari.enabled: false` до
    финализации.

---

## Связанные документы

- [acme-server/docs/architecture.md](../../acme-server/docs/architecture.md) — текущая архитектура ACME.
- [acme-server/docs/schema.md](../../acme-server/docs/schema.md) — текущая схема `acme.db`.
- [acme-server/docs/ca-lifecycle.md](../../acme-server/docs/ca-lifecycle.md) — операции с root/intermediate, контекст для фичи 1.
- [acme-server/docs/dns-acme-peer.md](../../acme-server/docs/dns-acme-peer.md) — текущий деплой DNS+ACME-пира.
