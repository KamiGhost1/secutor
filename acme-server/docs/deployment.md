# Деплой

## Тома

| путь в контейнере           | источник                                | режим | назначение                                  |
|-----------------------------|-----------------------------------------|-------|---------------------------------------------|
| `/secutor/context`          | `~/.secutor/contexts/<name>/` хоста     | **ro**| CA-ключ, сертификат, метаданные контекста   |
| `/var/lib/secutor-acme`     | named volume `secutor-acme-data`        | rw    | `acme.db` (стейт сервера)                   |
| `/run/secrets/...`          | Docker secrets                          | ro    | пароль контекста, токены DNS-провайдеров    |
| `/etc/secutor-acme`         | bind или configmap                      | ro    | `config.yaml` (резолверы, политика, порты)  |

CA-стор монтируется **read-only**. Сервер ни при каких условиях не должен туда писать. Все изменения (CRL, журналы выпусков) идут в свою БД либо обратно через CLI на хосте.

## Переменные окружения

| переменная                          | назначение                                                |
|-------------------------------------|-----------------------------------------------------------|
| `SECUTOR_CONTEXT_DIR`               | `/secutor/context`                                        |
| `SECUTOR_CONTEXT_PASSWORD_FILE`     | `/run/secrets/context_password`                           |
| `SECUTOR_ACME_DB`                   | `/var/lib/secutor-acme/acme.db`                           |
| `SECUTOR_ACME_CONFIG`               | `/etc/secutor-acme/config.yaml`                           |
| `SECUTOR_ACME_LISTEN`               | `0.0.0.0:8443` (ACME API)                                 |
| `SECUTOR_ACME_BASE_URL`             | `https://acme.example/`, публикуется в `directory`        |

**Принцип**: никаких секретов в `*_VALUE` env. Только `*_FILE` → путь к секрету. Это убирает их из `docker inspect`, `ps eww`, логов оркестратора.

## Docker secrets

### docker compose

```yaml
services:
  acme:
    image: secutor-acme:1.0.0
    read_only: true
    volumes:
      - type: bind
        source: ${HOME}/.secutor/contexts/prod
        target: /secutor/context
        read_only: true
      - secutor-acme-data:/var/lib/secutor-acme
      - ./config.yaml:/etc/secutor-acme/config.yaml:ro
    environment:
      SECUTOR_CONTEXT_DIR: /secutor/context
      SECUTOR_CONTEXT_PASSWORD_FILE: /run/secrets/context_password
      SECUTOR_ACME_DB: /var/lib/secutor-acme/acme.db
      SECUTOR_ACME_CONFIG: /etc/secutor-acme/config.yaml
      SECUTOR_ACME_BASE_URL: https://acme.lan/
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
