# Деплой

> **Перед деплоем — подготовь CA.** Этот документ описывает, как разворачивается ACME-сервер, **предполагая**, что CA уже создана и intermediate context готов к доставке. Если ты только начинаешь — иди в [ca-lifecycle.md](ca-lifecycle.md): там пошагово про создание root + intermediate, бэкапы, ротацию и отзыв. В контейнер монтируется **intermediate** (не root!) — root остаётся оффлайн.

## Тома

| путь в контейнере           | источник                                | режим | назначение                                  |
|-----------------------------|-----------------------------------------|-------|---------------------------------------------|
| `/secutor/context`          | `~/.secutor/contexts/<name>/` хоста     | **ro**| CA-ключ, сертификат, метаданные контекста   |
| `/secutor/tls`              | папка с bootstrap-cert+key              | **ro**| TLS для самого ACME-эндпоинта (HTTPS-режим) |
| `/var/lib/secutor-acme`     | named volume `secutor-acme-data`        | rw    | `acme.db` (стейт сервера)                   |
| `/run/secrets/...`          | Docker secrets                          | ro    | пароль контекста, токены DNS-провайдеров    |
| `/etc/secutor-acme`         | bind или configmap                      | ro    | `config.yaml` (резолверы, политика, порты)  |
| `/tmp`                      | **tmpfs** (RAM-диск)                    | rw    | временный файл расшифрованного store.db     |

CA-стор монтируется **read-only**. Сервер ни при каких условиях не должен туда писать. Все изменения (CRL, журналы выпусков) идут в свою БД либо обратно через CLI на хосте.

В `/secutor/context` монтируется **intermediate** context, не root. Root CA не должен попадать на сервер ACME ни в каком виде, кроме публичной части `cert.pem` (для отдачи trust anchor клиентам). Подробнее — [ca-lifecycle.md](ca-lifecycle.md).

### Содержимое `/secutor/context`

В монтируемой папке должны лежать **ровно два файла**:

```
context.json    # метаданные (соль, итерации pbkdf2, верификатор пароля)
store.enc       # зашифрованная SQLite БД со всеми CA (root + intermediate + leaf)
                # ИЛИ store.db — то же, но без шифрования
```

Загрузчик ([contextLoader.ts:99-110](../src/server/contextLoader.ts)) ищет именно `store.enc` или `store.db` на верхнем уровне. Если ты случайно скопировал вложенную структуру (типа `context/intermediate/store.enc`), сдвинь файлы на уровень выше — иначе получишь `No store.enc or store.db in <path>`.

Все CA лежат **в одной БД** связанные через `issuer_id`. ACME выбирает подписывающую CA по имени (`SECUTOR_CA_CERT_NAME` или первую по id) и автоматически строит цепочку до самоподписанного корня.

### tmpfs обязательна при `read_only: true`

`secutor-acme` при загрузке контекста делает три действия:
1. Читает `store.enc` (encrypted).
2. Расшифровывает его в память.
3. **Пишет распакованную SQLite во временный файл** в `/tmp` (с правами 0600), открывает SQLite в read-only режиме, и в `finally` удаляет файл.

Шаг 3 нужен потому, что `better-sqlite3` (нативный модуль) работает только с файлами, не с in-memory буферами. Расшифрованный blob нужно положить в файловую систему хотя бы временно.

С `read_only: true` корневая ФС контейнера запрещена на запись, включая `/tmp` — шаг 3 падает с `EROFS: read-only file system`. Лечение — RAM-диск под `/tmp`:

```yaml
tmpfs:
  - /tmp:rw,noexec,nosuid,size=64m
```

⚠️ **Не клади `SECUTOR_CONTEXT_DIR` внутрь `/tmp`** — tmpfs перекроет твой bind-mount. Используй любой другой путь, например `/secutor/context`.

## Переменные окружения

| переменная                          | назначение                                                |
|-------------------------------------|-----------------------------------------------------------|
| `SECUTOR_CONTEXT_DIR`               | `/secutor/context`                                        |
| `SECUTOR_CONTEXT_PASSWORD_FILE`     | `/run/secrets/context_password`                           |
| `SECUTOR_ACME_DB`                   | `/var/lib/secutor-acme/acme.db`                           |
| `SECUTOR_ACME_CONFIG`               | `/etc/secutor-acme/config.yaml`                           |
| `SECUTOR_ACME_LISTEN`               | `0.0.0.0:8443` (ACME API)                                 |
| `SECUTOR_ACME_BASE_URL`             | `https://acme.example/`, публикуется в `directory`        |
| `SECUTOR_ACME_TLS_CERT`             | путь к bootstrap-cert (опционально, см. ниже) — `/secutor/tls/acme.lan.vpn.crt` |
| `SECUTOR_ACME_TLS_KEY`              | путь к приватному ключу bootstrap-cert (опционально) — `/secutor/tls/acme.lan.vpn.key` |

**Принцип**: никаких секретов в `*_VALUE` env. Только `*_FILE` → путь к секрету. Это убирает их из `docker inspect`, `ps eww`, логов оркестратора.

## HTTP vs HTTPS на ACME-эндпоинте

ACME RFC 8555 §6.1 требует, чтобы directory отдавался по HTTPS. Все распространённые ACME-клиенты (lego в Traefik, certbot, acme.sh) отказываются работать с plain-HTTP URL'ами. Поэтому в проде секутор должен отвечать по HTTPS.

Секутор поддерживает **два режима**:

| Режим | `baseUrl` | TLS-терминация | Когда выбирать |
|---|---|---|---|
| **HTTPS встроенный** (рекомендуется) | `https://acme.lan.vpn:8443/` | внутри секутора, через `tls.{certFile,keyFile}` или env `SECUTOR_ACME_TLS_CERT/KEY` | базовый сценарий: один контейнер обслуживает и TLS, и ACME |
| **HTTP за reverse proxy** | `https://acme.lan.vpn/` (внешний URL!) | nginx/traefik снаружи, secutor слушает HTTP на 127.0.0.1 | уже есть reverse proxy в стеке, хочется централизовать сертификаты в нём |

### Bootstrap-сертификат для самого acme.lan.vpn

Чтобы `acme.lan.vpn` отвечал по HTTPS, нужен TLS-сертификат на это имя. Получить его через ACME нельзя — ACME ещё не работает (классическая курица-яйцо). Способы:

1. **Через TUI секутора** (`secutor` без аргументов): открыть контекст intermediate, выпустить сертификат с CN/SAN = `acme.lan.vpn` и EKU `serverAuth`, экспортировать в PEM. Это правильный путь для прода.
2. **Самоподписанный временный**: `openssl req -x509 -newkey rsa:2048 -days 365 -nodes ...`. Подходит для PoC. Клиентам в `LEGO_CA_CERTIFICATES` (или системный trust store) надо положить эту же подделку как доверенный root — иначе lego не пройдёт handshake.

После старта секутор пишет в лог `secutor-acme ready — listening HTTPS on ...`. Если видишь `HTTP` — переменные `SECUTOR_ACME_TLS_*` либо не заданы, либо файлы недоступны.

### Co-located клиенты

Если ACME-клиент работает в **том же docker-compose**, что и secutor, он обращается к нему через `https://127.0.0.1:8443/directory` (через `service:wg` namespace) или `https://acme:8443/directory` (через bridge). Bootstrap-cert будет подписан root'ом из `/ca.pem` — этот root надо отдать lego через `LEGO_CA_CERTIFICATES`.

Пример в Traefik:
```yaml
command:
  - --certificatesresolvers.internal.acme.caserver=https://127.0.0.1:8443/directory
environment:
  - LEGO_CA_CERTIFICATES=/certs/ca.pem
volumes:
  - ./acme/tls/ca.pem:/certs/ca.pem:ro
```

В acme.sh / certbot:
```bash
acme.sh --issue ... --server https://acme.lan.vpn:8443/directory
# если root CA не в системном trust store:
SSL_CERT_FILE=/path/to/ca.pem acme.sh --issue ...
```

## Docker secrets

### docker compose

```yaml
services:
  acme:
    image: secutor-acme:1.0.0
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m       # обязательно при read_only
    volumes:
      - type: bind
        source: ${HOME}/.secutor/contexts/prod
        target: /secutor/context             # вне /tmp, иначе tmpfs перекроет
        read_only: true
      - ./tls:/secutor/tls:ro                # bootstrap-cert для acme.lan.vpn
      - secutor-acme-data:/var/lib/secutor-acme
      - ./config.yaml:/etc/secutor-acme/config.yaml:ro
    environment:
      SECUTOR_CONTEXT_DIR: /secutor/context
      SECUTOR_CONTEXT_PASSWORD_FILE: /run/secrets/context_password
      SECUTOR_ACME_DB: /var/lib/secutor-acme/acme.db
      SECUTOR_ACME_CONFIG: /etc/secutor-acme/config.yaml
      SECUTOR_ACME_BASE_URL: https://acme.lan/
      # TLS пути — env-переменные эквивалентны полю `tls:` в config.yaml,
      # env wins при конфликте. Указывай в ОДНОМ месте.
      SECUTOR_ACME_TLS_CERT: /secutor/tls/acme.lan.crt
      SECUTOR_ACME_TLS_KEY:  /secutor/tls/acme.lan.key
    secrets:
      - context_password
      - dns_rfc2136_key
    ports:
      - "8443:8443"

secrets:
  context_password:
    file: ./secrets/context_password.txt
  dns_rfc2136_key:
    file: ./secrets/rfc2136.key

volumes:
  secutor-acme-data:
```

Файлы из `./secrets/` — `chmod 0600`, не коммитятся в git (добавить в `.gitignore`). В проде — внешний secret-стор (Vault, SOPS, sealed-secrets), который рендерит файлы на хосте перед запуском compose.

### Права bind-mount'ов

| Bind-mount | Содержит | Права директории | Права файлов |
|---|---|---|---|
| `~/.secutor/contexts/prod` → `/secutor/context` | приватный ключ CA + метаданные | `700` | `600` |
| `./secrets/` → `/run/secrets/*` | пароль контекста | `700` | `600` |
| `./config.yaml` → `/etc/secutor-acme/config.yaml` | конфиг (не секрет) | — | `644` |

**Важно**: директории требуют бит `x` (execute) для traversal. Если ставить через `chmod -R 600 dir/` или `rsync --chmod=600` — директории становятся `rw-` без `x`, и процесс внутри контейнера получает permission denied при попытке прочитать ЛЮБОЙ файл (даже если файлы открыты на чтение).

Правильно:
```bash
chmod 700 dir         # директория: rwx
chmod 600 dir/file    # файлы внутри: rw-
```

Или для rsync:
```bash
rsync -av --chmod=Du=rwx,Dg=,Do=,Fu=rw,Fg=,Fo= src/ dest/
#               ↑↑↑ Du = Directory User, Fu = File User
```

Не используй `--chmod=600` — это применит 600 и к директориям, без бита `x`.

### swarm / kubernetes

В Swarm — `secrets: external: true`, ссылка на уже созданный секрет (`docker secret create`).
В k8s — `Secret` + `volumeMounts` на `/run/secrets/<name>`, ровно та же семантика. Код сервера не различает оркестратор.

## Разблокировка контекста

При старте сервер:
1. Читает `SECUTOR_CONTEXT_PASSWORD_FILE`.
2. Через `verifyContextPassword()` проверяет пароль.
3. Расшифровывает `store.enc` через `migrateContextEncryption`/equivalent в память (не на диск).
4. Загружает CA-ключ и сертификат, держит их в памяти на время жизни процесса.
5. Никуда пароль не логирует, не отдаёт по API, после загрузки забывает (можно занулить буфер).

Если пароль неверный — процесс падает с кодом ≠0. Никаких ретраев — это сигнал оркестратору, что секрет битый.

### Альтернатива: unlock по запросу

Вместо файла-секрета — эндпоинт `POST /admin/unlock` с паролем по mTLS от админа. Плюс: пароль не лежит на диске вообще. Минус: рестарт = ручное действие, не подходит для автоматической оркестрации. Можно реализовать как второй режим (`SECUTOR_UNLOCK_MODE=file|api`), но не в v1.

## Сетевая модель

- 8443/tcp (или другой) — ACME API, наружу.
- 80/tcp — нужен **только** если включён HTTP-01 challenge и сервер сам валидирует. Можно слушать на том же процессе либо вынести.
- DNS — исходящие, к резолверам из конфига.
- Сервер сам **не** держит DNS-зону. Размещение TXT — задача клиента (через RFC 2136 / провайдера / acme-dns).

## Логи и мониторинг

- stdout/stderr — структурированный JSON. Никаких приватных ключей, токенов, паролей.
- `audit_log` таблица — источник правды по выпускам, дублируется в stdout для внешнего sink'а (Loki/ELK).
- Метрики: prometheus на отдельном порту (`/metrics`), без аутентификации (внутренний скрейп). Счётчики: выпуски, отказы по challenge, latency валидации DNS, размер очереди валидатора.

## Бэкап

- `acme.db` — обычный SQLite VACUUM INTO в крон-джобе на хосте → внешнее хранилище.
- CA-стор бэкапится отдельно средствами secutor CLI.
- Секреты — из source-of-truth (Vault/SOPS), не из контейнера.

## Что не делаем в v1

- Auto-rotation пароля контекста.
- HA / репликация. Один инстанс. Для HA нужен общий стейт-стор (Postgres вместо SQLite) — это отдельная задача.
- Встроенный reverse-proxy. TLS-терминация снаружи (nginx/traefik/caddy).
