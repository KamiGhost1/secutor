# Траблшутинг и runbook

Список конкретных проблем с диагностикой и решениями. Если ваша не сюда — заведите issue с логом сервера + точным запросом клиента.

## Содержание

- [Где смотреть логи](#где-смотреть-логи)
- [Сервер не стартует](#сервер-не-стартует)
- [Клиент: ошибки JWS](#клиент-ошибки-jws)
- [Challenge не проходит](#challenge-не-проходит)
- [Finalize падает](#finalize-падает)
- [TLS на ACME-эндпоинте](#tls-на-acme-эндпоинте)
- [Тюнинг производительности](#тюнинг-производительности)
- [Полезные SQL-запросы по acme.db](#полезные-sql-запросы-по-acmedb)
- [systemd-юнит](#systemd-юнит)
- [Шпаргалка по эндпоинтам](#шпаргалка-по-эндпоинтам)

---

## Где смотреть логи

```bash
docker logs -f --tail 200 secutor-acme            # самый главный лог
docker logs -f --tail 200 bind                    # если используете BIND
journalctl -u wg-quick@wg0 -f                     # WG handshake / маршруты
```

Внутри ACME-логов искать:
- `worker tick` — фоновый воркер запустился.
- `challenge.valid` / `challenge.invalid` — результат валидации.
- `cert.issue` / `cert.revoke` — выпуск/отзыв.

Все события также пишутся в таблицу `audit_log` в `acme.db`.

## Сервер не стартует

### `Context decryption failed: wrong password or corrupted file`

Пароль в `/run/secrets/context_password` не подходит к `store.enc`. Проверьте:

```bash
# Что лежит в секрете (учтите trailing newline):
docker exec secutor-acme cat /run/secrets/context_password | xxd | head -2
```

Проверьте пароль на хосте через secutor TUI: откройте контекст с тем же паролем — если открывается, значит файл секрета битый (например, BOM, неправильная кодировка, или лишний `\n`).

```bash
# Перезаписать без trailing newline
printf '%s' 'YOUR-REAL-PASSWORD' > ./secrets/context_password.txt
chmod 600 ./secrets/context_password.txt
```

### `No CA certificate in context`

В контексте нет ни одного сертификата `type='ca'`. Создайте через secutor TUI: `Create CA`. Или укажите конкретное имя через `SECUTOR_CA_CERT_NAME=<имя>`, если в контексте несколько CA.

### `SECUTOR_ACME_BASE_URL not set`

Обязательная переменная. Это публичный URL, под которым клиенты будут ходить — оно идёт во все Location-заголовки и `directory`. Например `http://acme.lan:8443/` или `https://acme.example.com/`.

### `EADDRINUSE`

Кто-то занял порт. `sudo lsof -i :8443` или поменяйте `SECUTOR_ACME_LISTEN`.

## Клиент: ошибки JWS

### `urn:ietf:params:acme:error:badNonce`

Клиент использовал nonce, который сервер не знает / уже потратил / он истёк. Наш клиент сам перезапрашивает 1 раз при badNonce. Если повторяется — часы на сервере и клиенте сильно расходятся, либо клиент кеширует nonce между процессами.

### `urn:ietf:params:acme:error:unauthorized: JWS url mismatch`

В JWS protected header клиент кладёт `url`, который должен **точно** совпасть с URL-ом запроса. Если ваш `SECUTOR_ACME_BASE_URL` — это `https://acme.lan/`, а клиент стучится по `https://10.10.0.1/`, то URL не совпадает. Сделайте `acme.lan` резолвящимся на нужный IP (см. [vpn-setup.md](vpn-setup.md)).

### `accountDoesNotExist: Unknown kid`

Клиент пытается использовать `kid` (URL аккаунта), которого нет в acme.db. Чаще всего — вы пересоздали acme.db, а у клиента закеширован старый kid. Удалите клиентский account.key (для встроенного клиента) или `accounts/` в `cb-config/` (для certbot) — пересоздастся.

### `badSignatureAlgorithm`

Сервер поддерживает: `RS256/384/512, PS256/384/512, ES256/384/512, EdDSA`. Если клиент пытается со старым `HS256` или совсем экзотикой — обновите клиент.

## Challenge не проходит

### `incorrectResponse: No TXT records at _acme-challenge.X`

ACME-сервер пошёл резолвить TXT и не нашёл записи. Проверки по порядку:

1. **Запись вообще есть?**
   ```bash
   dig @10.10.0.1 _acme-challenge.web.lan TXT +short
   ```
   Пусто → ваш DNS-хук не сработал, либо запись ещё не реплицировалась.

2. **Сервер ходит за DNS туда, куда нужно?**
   В `config.yaml` → `resolvers`. Если зона `lan` не в специфичном правиле и сервер пошёл в публичный `1.1.1.1`, тот вернёт `NXDOMAIN`. Лог в дебаг-режиме (`LOG_LEVEL=debug`) покажет, какой резолвер выбран.

3. **Запись есть, но имя не то.** Клиент должен публиковать ровно `_acme-challenge.<value-из-identifier>`. Для wildcard `*.foo.lan` — это `_acme-challenge.foo.lan` (без `*`).

4. **Значение не то.** TXT должен быть `base64url(SHA256(token || "." || JWK_thumbprint))`. Если ваш auth-hook пишет голый token — это HTTP-01 формат, не DNS-01. Сертбот и наш клиент считают сами; кастомный скрипт — должен брать `CERTBOT_VALIDATION` / `ACME_RECORD_VALUE` 1-в-1.

### `TXT record at <name> does not match expected key authorization`

Запись нашлась, но значение не то. Скорее всего, клиент пробует тот же challenge с другим аккаунтом (другим thumbprint'ом) — например, удалили локальный account.key но забыли почистить старую TXT-запись. Удалите запись и попробуйте ещё раз.

### HTTP-01 — `HTTP 404 at <url>`

Сервер ACME постучался на `http://<имя>:80/.well-known/acme-challenge/<token>` и получил 404. Значит:
- либо ваш http-сервер не настроен отдавать `/.well-known/acme-challenge/`;
- либо ACME-сервер пошёл не на тот хост (`<имя>` резолвится не туда, куда вы ожидаете);
- либо файрвол между ACME-сервером и клиентом блокирует 80/tcp.

### HTTP-01 — `HTTP timeout`

ACME-сервер не дозвонился до клиента вообще. В VPN-сценарии — убедитесь, что ACME-сервер видит peer'а: с hub'а должно резолвиться `web.lan` → `10.10.0.10`, и `curl http://web.lan/` должен работать.

## Finalize падает

### `badCSR: CSR signature invalid`

CSR пришёл, но self-signature не сходится. Чаще всего — мусор в передаче (например, base64url с padding, который клиент ошибочно вставил). Наш клиент кодирует правильно, у certbot тоже корректно.

### `badCSR: CSR missing SAN <name>`

Клиент сгенерировал CSR с не теми SAN'ами, что в заказе. ACME запрещает добавлять/удалять имена на финализации. Совпадение строгое (как множество).

### `serverInternal: Signing failed`

Падение `node:crypto.sign` или `node-forge` при выпуске. Чаще всего из-за неподдерживаемого алгоритма у CA. Поддерживаемые алгоритмы CA: RSA-2048/3072/4096, ECDSA P-256/P-384, Ed25519. Если у вас экзотика — сообщите.

## TLS на ACME-эндпоинте

Наш сервер сам не делает TLS. Это **специально** — стандартный паттерн:

1. **WG-only**: HTTP по WG достаточно (WG уже шифрует). `http://acme.lan:8443/` — ок.
2. **Публичный доступ**: ставим перед ACME reverse-proxy.

### nginx как TLS-фронт

```nginx
server {
    listen 443 ssl http2;
    server_name acme.example.com;

    ssl_certificate /etc/letsencrypt/live/acme.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/acme.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        client_max_body_size 1m;
    }
}
```

В этом случае `SECUTOR_ACME_BASE_URL=https://acme.example.com/` и `SECUTOR_ACME_LISTEN=127.0.0.1:8443`.

### Caddy (автоматический TLS из публичного LE)

```caddy
acme.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

Caddy сам выпустит и обновит cert.

### Загвоздка с CA-замкнутостью

Если ACME-сервер сам выпускает cert на свой эндпоинт через тот же CA — клиентам, которые ещё не доверяют CA, будет нечем верифицировать TLS. Bootstrap делается так: первое доверие к CA — через копию `ca.pem` (через provisioning), а уже потом всё работает.

## Тюнинг производительности

Сервер — Node + fastify + SQLite. На одной машине без проблем держит сотни выпусков в час. Узкие места по убыванию вероятности:

1. **SQLite locking** (WAL включен — обычно не проблема). Если несколько процессов пишут — нет, у нас один.
2. **Воркер с long-running DNS-запросами**. Тикает раз в 1.5с, делает до 20 challenge'ей за тик. Если DNS медленный — увеличьте параллельность (в `worker.ts` сейчас sequential).
3. **Подпись cert'ов**. RSA-4096 CA — медленно. ECDSA P-256 CA — мгновенно.

Метрики (TODO в v0.2): prometheus endpoint на `:9100/metrics`. Пока — смотрите по `audit_log`:

```sql
SELECT date(ts), action, COUNT(*)
FROM audit_log
WHERE ts > date('now','-7 days')
GROUP BY 1, 2;
```

## Полезные SQL-запросы по acme.db

Открыть:

```bash
docker exec -it secutor-acme sqlite3 /var/lib/secutor-acme/acme.db
```

### Кто что выпустил за последние сутки

```sql
SELECT
  c.issued_at,
  c.serial_hex,
  json_extract(o.identifiers_json, '$') AS identifiers,
  a.contact_json
FROM certificates c
JOIN orders o ON o.id = c.order_id
JOIN accounts a ON a.id = c.account_id
WHERE c.issued_at > datetime('now', '-1 day')
ORDER BY c.issued_at DESC;
```

### Активные неудавшиеся заказы

```sql
SELECT id, account_id, status, identifiers_json, error_json
FROM orders
WHERE status = 'invalid'
  AND created_at > datetime('now', '-7 days');
```

### Деактивировать аккаунт (скомпрометированный клиент)

```sql
UPDATE accounts SET status = 'deactivated' WHERE id = 'ULID_АККАУНТА';
```

После этого все его последующие запросы будут отбиты на JWS-стадии.

### Поправить allow-list для одного аккаунта

```sql
UPDATE accounts
SET allow_list_json = json_array('*.lan', 'foo.example.com')
WHERE id = 'ULID_АККАУНТА';
```

(в текущей версии глобальный allow-list имеет приоритет; per-account allow-list — точка расширения)

### Сколько nonces висит

```sql
SELECT COUNT(*) FROM nonces WHERE expires_at > datetime('now');
```

Должно быть скромно (≤ числа активных клиентов × 1-2).

## systemd-юнит

Для бесконтейнерного запуска или клиента-обновлятора:

`/etc/systemd/system/secutor-acme-renew.service`:

```ini
[Unit]
Description=Renew certificates from secutor ACME
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/secutor-acme-client \
    --directory http://acme.lan:8443/directory \
    --domain web.lan \
    --challenge dns-01 --dns-hook rfc2136 \
    --rfc2136-server 10.10.0.1 --rfc2136-zone lan \
    --rfc2136-key /etc/secutor-certs/nsupdate.key \
    --out /etc/secutor-certs/web.lan \
    --account-key /etc/secutor-certs/account.key
ExecStartPost=/bin/systemctl reload nginx
User=root
```

`/etc/systemd/system/secutor-acme-renew.timer`:

```ini
[Unit]
Description=Weekly renew

[Timer]
OnCalendar=Mon 03:00
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now secutor-acme-renew.timer
```

## Шпаргалка по эндпоинтам

| Метод   | URL                | Назначение                                            | Auth      |
|---------|--------------------|-------------------------------------------------------|-----------|
| GET     | `/directory`       | таблица URL'ов всех остальных эндпоинтов              | none      |
| HEAD/GET| `/new-nonce`       | свежий `Replay-Nonce`                                 | none      |
| POST    | `/new-account`     | создать/найти аккаунт по JWK                          | JWS jwk   |
| POST    | `/acct/:id`        | получить/обновить аккаунт                             | JWS kid   |
| POST    | `/new-order`       | создать новый order на список доменов                 | JWS kid   |
| POST    | `/order/:id`       | прочитать order (POST-as-GET)                         | JWS kid   |
| POST    | `/authz/:id`       | прочитать authorization                               | JWS kid   |
| POST    | `/chall/:id`       | триггернуть валидацию challenge                       | JWS kid   |
| POST    | `/order/:id/finalize` | прислать CSR и получить сертификат                 | JWS kid   |
| POST    | `/cert/:id`        | скачать выпущенный сертификат (PEM chain)             | JWS kid   |
| POST    | `/revoke-cert`     | отозвать сертификат                                   | JWS kid   |
| GET     | `/ca.pem`          | **root** CA в PEM (для trust store)                   | **none**  |
| GET     | `/chain.pem`       | signing CA + промежуточные (без root)                 | **none**  |
| GET     | `/crl`             | актуальный CRL в DER                                  | **none**  |
| GET     | `/crl.pem`         | то же в PEM                                           | **none**  |
