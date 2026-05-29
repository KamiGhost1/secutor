# Настройка администрирования secutor-acme

Этот гайд — пошаговая инструкция по включению admin API (mTLS) поверх
уже работающего ACME-сервера. После прохождения всех шагов будет:

- отдельный HTTPS-listener на порту `8444` с обязательной mTLS-аутентификацией;
- набор admin-сертификатов с ролями (`viewer` / `operator` / `owner`);
- возможность управлять хабом через `secutor` TUI (вкладка **🌐 Hubs**)
  или из своих скриптов через `curl`;
- (опционально) server-managed DNS-01 — хаб сам публикует TXT-записи
  через сконфигурированного провайдера.

Эталонный reference по самим endpoint'ам — [admin-api.md](admin-api.md).
Здесь — только setup.

## Содержание

- [Что мы получим](#что-мы-получим)
- [Pre-requisites](#pre-requisites)
- [Шаг 1. Серверный TLS-сертификат для admin-listener](#шаг-1-серверный-tls-сертификат-для-admin-listener)
- [Шаг 2. Клиентские сертификаты администраторов](#шаг-2-клиентские-сертификаты-администраторов)
- [Шаг 3. Выбор trust-модели](#шаг-3-выбор-trust-модели)
- [Шаг 4. Доработка config.yaml](#шаг-4-доработка-configyaml)
- [Шаг 5. Деплой и порт](#шаг-5-деплой-и-порт)
- [Шаг 6. Smoke-проверка через curl](#шаг-6-smoke-проверка-через-curl)
- [Шаг 7. Подключение TUI](#шаг-7-подключение-tui)
- [Опционально: server-managed DNS-01](#опционально-server-managed-dns-01)
- [Опционально: hub keystore для CI / shared-машин](#опционально-hub-keystore-для-ci--shared-машин)
- [Ротация admin-сертификатов](#ротация-admin-сертификатов)
- [Безопасность](#безопасность)
- [Troubleshooting](#troubleshooting)
- [Чек-лист](#чек-лист)

## Что мы получим

Архитектурно admin поднимается как **второй fastify-инстанс** в том же
процессе, на **отдельном порту**, с собственным TLS-конфигом и
обязательной mTLS-аутентификацией. Существующий ACME-эндпоинт (порт 8443)
не меняется — стандартные клиенты (certbot, acme.sh, cert-manager,
Traefik) ничего не замечают.

Что делается через admin (полностью изолировано от обычного RFC 8555):

- инвентаризация и фильтрация сертификатов, отзыв (операторская роль);
- бан аккаунтов с каскадным отзывом всех валидных серти (owner);
- статистика по ордерам, top-причин провала, Prometheus-метрики;
- CA rotation (stage → promote → rollback), reissue-worker;
- admin-issue (выпуск в обход challenge'ей);
- ARI hint endpoint для совместимых клиентов;
- (опц.) server-managed DNS-01.

## Pre-requisites

- ACME-сервер уже работает на порту 8443 (см. [usage.md](usage.md)).
- Установлен `secutor` 1.2+ на админской машине (для генерации
  сертификатов и для TUI).
- К хабу есть LAN/VPN-доступ — admin-порт **не** должен светить в
  публичный интернет.

## Шаг 1. Серверный TLS-сертификат для admin-listener

Admin-listener использует свой собственный TLS-сертификат, **независимый**
от ACME-CA, которым подписываются leaf'ы. Можно сделать любой
self-signed — TUI всё равно пинит fingerprint, OS trust-store роли не
играет.

На админской машине, в `secutor` TUI:

1. Создай отдельный контекст `admin-srv` (можно без пароля).
2. `+ Create CA` → `admin-srv-root`, ed25519, validity 5 лет.
3. `+ Issue server cert`:
   - name: `admin-listener`
   - CN: `acme.lan.vpn` (или твой FQDN/IP хаба)
   - SAN: `acme.lan.vpn`, при IP — добавь IP в SAN тоже
   - validity: 2 года
   - algorithm: ecdsa-p256

Экспортируй cert+key в файлы:

```
cert details → E → save cert → admin-server.crt
cert details → E → save key  → admin-server.key
```

Скопируй на хаб:

```bash
scp admin-server.crt admin-server.key services-host:/tmp/
ssh services-host
sudo install -m 600 -o root /tmp/admin-server.{crt,key} /secutor/
```

## Шаг 2. Клиентские сертификаты администраторов

Каждому администратору — свой leaf-сертификат с `type=client`. Это и есть
«удостоверение личности» для admin API: hub видит SHA-256(cert DER) и
маппит на роль.

В `secutor` TUI:

1. Создай контекст `admin-clients` (или используй существующий).
2. `+ Create CA` → `admin-cli-root`, ed25519, 5 лет.
3. `+ Issue client cert` для каждого админа:
   - `ops-admin` (роль owner — для тех, кто будет банить и рейзить CA),
   - `noc-engineer` (роль operator — для отзывов),
   - `ci-runner` (роль operator — для CI),
   - `dashboards` (роль viewer — для read-only мониторинга).
   - Алгоритм: ed25519 для всех.

Собери fingerprint'ы клиентских сертификатов:

```bash
# Через TUI: cert details → видна строка SHA-256 fingerprint.
# Через openssl, если cert у тебя на диске:
openssl x509 -in ops-admin.crt -outform DER | sha256sum
# → abcdef0123456789...  -

# Через secutor CLI на dump'е контекста — нет, проще через TUI.
```

Запиши hex-fingerprint (без двоеточий, lowercase). Они пойдут в
`config.yaml` на следующем шаге.

Сами клиентские cert+key админы держат у себя:

```bash
# в TUI: cert details → E → save cert / save key
# admin кладёт их в ~/.secutor/hubkeys/<entry>/ или просто в файлы
```

## Шаг 3. Выбор trust-модели

Два независимых пути доверия — можно комбинировать:

**A. Fingerprint allow-list** (рекомендую для команды ≤ 5–10 человек).

- Плюсы: точечный контроль, отзыв = удалить строку из конфига.
- Минусы: добавление нового админа — restart хаба.

**B. CA + subjectMatch** (для больших команд / CI-флота).

- Плюсы: выпустил новому inhouse admin-CA → автоматически имеет роль.
- Минусы: нет точечного отзыва без CRL/OCSP инфраструктуры.

При совпадении нескольких правил выигрывает **самая высокая** роль
(owner > operator > viewer). Маппинг на роль происходит ПОСЛЕ TLS
handshake'а — на handshake принимается любой клиентский cert
(`requestCert: true, rejectUnauthorized: false`), фактическое решение
делает app-level middleware.

## Шаг 4. Доработка config.yaml

На хабе, в файле, который пробрасывается как `SECUTOR_ACME_CONFIG`,
добавь блок `admin:`. Полный пример (можно вставить целиком и потом
почистить):

```yaml
# ─── существующие ACME-настройки (не трогаем) ───
listen: "0.0.0.0:8443"
baseUrl: "https://acme.lan.vpn:8443/"
contextDir: /secutor/context
contextPasswordFile: /run/secrets/context_password
stateDb: /var/lib/secutor-acme/acme.db
resolvers:
  - zones: ["lan.vpn"]
    servers: ["10.0.0.53"]
  - zones: ["*"]
    servers: ["1.1.1.1", "8.8.8.8"]
challenges:
  dns01: true
  http01: true
leafValidityDays: 90
nonceTtlSec: 600
orderTtlSec: 604800

# ─── НОВОЕ: admin API ───
admin:
  listen: "0.0.0.0:8444"            # отдельный порт; не выставляй в публичный интернет!
  serverTls:
    certFile: /secutor/admin-server.crt
    keyFile:  /secutor/admin-server.key
  trust:
    # Модель A — fingerprints.
    fingerprints:
      - sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        role: owner
        label: "ops-admin"
      - sha256: "1111111111111111111111111111111111111111111111111111111111111111"
        role: operator
        label: "noc-engineer"
      - sha256: "2222222222222222222222222222222222222222222222222222222222222222"
        role: operator
        label: "ci-runner"
      - sha256: "3333333333333333333333333333333333333333333333333333333333333333"
        role: viewer
        label: "dashboards"

    # Модель B — независимый admin-CA + subjectMatch.
    # cas:
    #   - caFile: /secutor/admin-ca.pem
    #     subjectMatch: "OU=NOC"
    #     role: operator
    #   - caFile: /secutor/corp-mdm.pem
    #     subjectMatch: "OU=ops"
    #     role: viewer

    publishPolicy: false              # true только если хочешь раздавать /auth-policy без mTLS
  banMode: cascade                    # 'cascade' (по умолчанию) | 'soft'
```

Если включаешь модель B — положи CA-файл рядом с серверным сертом:

```bash
scp admin-cli-root.crt services-host:/tmp/
sudo install -m 644 /tmp/admin-cli-root.crt /secutor/admin-ca.pem
```

(CA-файл публичный, чтение всем — норма.)

## Шаг 5. Деплой и порт

В `docker-compose.yaml`:

```yaml
services:
  acme:
    image: secutor-acme:0.2.0       # пересобери через `docker build acme-server/`
    ports:
      - "8443:8443"                 # ACME (как и было)
      - "127.0.0.1:8444:8444"       # NEW: admin API — bind на localhost / VPN-IP, НЕ 0.0.0.0
    volumes:
      - "$HOME/.secutor/contexts/prod:/secutor/context:ro"
      - "./acme-data:/var/lib/secutor-acme"
      - "./secrets/context_password.txt:/run/secrets/context_password:ro"
      - "./config.yaml:/secutor/config.yaml:ro"
      - "./admin-server.crt:/secutor/admin-server.crt:ro"
      - "./admin-server.key:/secutor/admin-server.key:ro"
      # При модели B:
      # - "./admin-cli-root.pem:/secutor/admin-ca.pem:ro"
      # При включённом server-managed DNS:
      # - "./tsig.key:/secutor/tsig.key:ro"
    environment:
      - SECUTOR_ACME_CONFIG=/secutor/config.yaml
      - SECUTOR_CONTEXT_DIR=/secutor/context
      - SECUTOR_CONTEXT_PASSWORD_FILE=/run/secrets/context_password
      - SECUTOR_ACME_DB=/var/lib/secutor-acme/acme.db
      - SECUTOR_ACME_BASE_URL=https://acme.lan.vpn:8443/
      - SECUTOR_ACME_LISTEN=0.0.0.0:8443
    restart: unless-stopped
```

> **Порт 8444.** Не bind'ай на `0.0.0.0`, если у хаба есть публичный
> интерфейс. Лучше всего — отдельный VPN-IP (`10.0.0.1:8444:8444`),
> либо проброс только через WireGuard/SSH-tunnel. Хотя mTLS защищает
> от анонимного доступа, минимизация поверхности атаки — это всегда
> хорошая практика.

Перезапуск:

```bash
docker compose down && docker compose up -d
docker compose logs -f acme
```

В логе ожидай:

```
secutor-acme ready — listening HTTPS on 0.0.0.0:8443 ...
admin API listening (mTLS) {"host":"0.0.0.0","port":8444}
```

Миграции БД `0002_admin`, `0003_dns_placements`, `0004_reissue_jobs`
применяются автоматически при первом старте — `acme.db` дополняется
новыми колонками/таблицами/индексами без ручных шагов.

## Шаг 6. Smoke-проверка через curl

С админской машины (или из VPN'а):

```bash
# 1. Без cert'а — должно отдать 401.
curl -sk https://acme.lan.vpn:8444/admin/v1/info
# → {"error":"mtls-required","detail":"No accepted client certificate"}

# 2. С неизвестным cert'ом — тоже 401.
curl -sk --cert intruder.crt --key intruder.key \
  https://acme.lan.vpn:8444/admin/v1/info
# → 401

# 3. С admin-cert'ом — OK.
curl -sk --cert ops-admin.crt --key ops-admin.key \
  https://acme.lan.vpn:8444/admin/v1/info | jq
# → {"role":"owner","ca":{...},"counts":{...}}

# 4. CA-метаданные.
curl -sk --cert ops-admin.crt --key ops-admin.key \
  https://acme.lan.vpn:8444/admin/v1/ca | jq

# 5. Метрики (для Prometheus).
curl -sk --cert ops-admin.crt --key ops-admin.key \
  https://acme.lan.vpn:8444/admin/v1/metrics

# 6. Стата по ордерам за последние 30 дней.
curl -sk --cert ops-admin.crt --key ops-admin.key \
  https://acme.lan.vpn:8444/admin/v1/stats/orders | jq
```

Если что-то идёт не так — см. [Troubleshooting](#troubleshooting) ниже.

## Шаг 7. Подключение TUI

На своей машине:

```bash
secutor
```

1. Из главного меню выбери **🌐 Hubs**.
2. Нажми `A` (Add hub).
3. Заполни:
   - **Display name** — `prod` (любое читаемое имя).
   - **Base URL** — `https://acme.lan.vpn:8444`.
4. Выбери источник клиентской идентичности:
   - **Cert from this context** — если ops-admin.crt лежит в текущем
     контексте secutor (рекомендую: безопасно и удобно).
   - **Cert/key files on disk** — указываешь абсолютные пути.
   - **Cert from hub keystore** — если предварительно положил cert+key
     в `~/.secutor/hubkeys/<entry>/` (см. ниже).
5. TUI делает первый запрос и показывает SHA-256 fingerprint сервера —
   проверь, что он совпадает с тем, что выпустил на Шаге 1, и нажми
   `Y` (TOFU-pin).

После этого попадёшь в **Hub session**. Доступные действия:

- 📜 Browse certificates (фильтр + revoke)
- 👥 Browse accounts (ban / unban)
- 📊 Stats dashboard
- 📋 Audit log
- 🔑 Verify CA private key — proof-of-possession против ожидаемого CA
- 🔄 Rotate CA / re-sign leaves — stage→promote→rollback + reissue job

## Опционально: server-managed DNS-01

Если хочешь, чтобы хаб сам публиковал TXT-запись для DNS-01 challenge'а
(вместо того, чтобы клиент это делал сам) — добавь в `config.yaml`:

```yaml
dnsProviders:
  - type: rfc2136
    zones: ["lan.vpn", "*.lan.vpn"]
    server: "10.0.0.53"
    keyFile: /secutor/tsig.key
    ttl: 30
  # - type: script
  #   zones: ["dev.lan"]
  #   path: /usr/local/bin/dev-dns-update.sh
```

`tsig.key` — BIND keyfile-формат:

```
key "acme-update." {
  algorithm hmac-sha256;
  secret "BASE64SECRETHERE==";
};
```

Скопируй на хаб (`0600`, owner=acme):

```bash
scp tsig.key services-host:/tmp/
sudo install -m 600 -o nobody /tmp/tsig.key /secutor/tsig.key
```

Смонтируй (`./tsig.key:/secutor/tsig.key:ro` в compose) и
перезапусти.

После рестарта **клиент** может попросить server-managed-режим, передав
расширение в `newOrder`:

```json
{
  "identifiers": [{"type": "dns", "value": "svc.lan.vpn"}],
  "secutor": {"dnsPlacement": "server-managed"}
}
```

Стандартные ACME-клиенты расширения не знают и игнорируют — для них
flow не меняется. Через TUI: при admin-issue из remote-сессии появится
галка «server-managed DNS» (когда provider для зоны сконфигурирован).

Полный гайд: [server-managed-dns.md](server-managed-dns.md).

## Опционально: hub keystore для CI / shared-машин

Если admin-cert не должен лежать внутри обычного PKI-контекста secutor
(например, выдан корпоративным MDM, или используется CI-агентом без UI):

```bash
mkdir -p ~/.secutor/hubkeys/ci-prod
chmod 700 ~/.secutor/hubkeys/ci-prod
install -m 600 ops-admin.crt ~/.secutor/hubkeys/ci-prod/cert.pem
install -m 600 ops-admin.key ~/.secutor/hubkeys/ci-prod/key.pem
cat > ~/.secutor/hubkeys/ci-prod/meta.json <<EOF
{
  "name": "ci-prod",
  "createdAt": "$(date -u +%FT%TZ)",
  "encrypted": false,
  "fingerprint": "<sha256 hex of cert DER>"
}
EOF
```

При добавлении хаба в TUI выбери `Cert from hub keystore` → `ci-prod`.

При необходимости шифрования приватника:

```bash
# Лучше делать через TUI: AddHub → 'Cert/key files on disk' →
# 'Import into hub-keystore (encrypted)' — пароль задаётся интерактивно.
```

## Ротация admin-сертификатов

### Плановая ротация client-cert'а

Выпусти новый client cert (через TUI). Возьми его SHA-256:

```bash
openssl x509 -in ops-admin-2026.crt -outform DER | sha256sum
```

На хабе добавь новый fingerprint в `config.yaml` рядом со старым:

```yaml
admin:
  trust:
    fingerprints:
      - sha256: "<новый fp>"
        role: owner
        label: "ops-admin (2026)"
      - sha256: "<старый fp>"
        role: owner
        label: "ops-admin (deprecated, remove after 2026-06-01)"
```

Перезапусти хаб. Дай админу время мигрировать. Удали старый fingerprint
после dead-line.

### Экстренный отзыв (украли key)

В `config.yaml` удали соответствующий fingerprint и сразу перезапусти
хаб. Через секунду украденный cert получает 401.

### Ротация серверного admin-cert'а

Выпусти новый serverTls cert, замени файлы на хабе, перезапусти.
**Обязательно** оповести админов — при первом подключении TUI после
ротации они увидят cert-pin-mismatch и должны будут заново
подтвердить fingerprint (TOFU). Без явного подтверждения подключение не
заработает.

## Безопасность

- **Порт 8444 — не в публичный интернет.** mTLS защищает от анонимного
  доступа, но не от 0-day в TLS-стеке. Бинди на localhost / VPN-IP.
- **Серверный TLS-cert админ-API независим от ACME-CA.** Можно
  self-signed — pin на стороне TUI решает.
- **`publishPolicy: true` раскрывает fingerprint'ы admin-клиентов**
  (без cert'ов). Это упрощает auto-discover в TUI, но даёт атакующему
  список «кому стоит phish'ить». В LAN-сетапах — ок, в публично
  выставленных хабах — лучше держать `false` и сообщать fingerprint'ы
  out-of-band.
- **Каждое мутирующее admin-действие** (revoke, ban, ca.promote,
  reissue.start, account.update, cert.issue.admin) попадает в
  `audit_log` с SHA-256 fingerprint'ом клиента — каждый админ
  отличим.
- **Backup `admin-server.key`.** Если потеряешь — потеряешь возможность
  принимать admin-подключения; придётся выпускать новый, рассылать
  fingerprint всем.
- **CRL для admin-cert'ов не предусмотрен.** Отзыв = удаление
  fingerprint'а из конфига + restart (для модели A), либо CRL на
  admin-CA (для модели B — требует, чтобы клиент проверял CRL, чего
  мы не делаем; так что для модели B отзыв = ротация admin-CA).

## Troubleshooting

### `runc create failed: ... make mountpoint ... read-only file system`

Полное сообщение примерно такое:

```
OCI runtime create failed: runc create failed: ... error mounting
"/opt/.../config.yaml" to rootfs at "/etc/secutor-acme/config.yaml":
make mountpoint "/etc/secutor-acme/config.yaml": read-only file system
```

Docker bind-mount файла требует, чтобы **сам файл-mountpoint** (или
содержащий его каталог, если файл будет создан в нём) уже существовал
в rootfs образа. Если ты монтируешь `./config.yaml` в
`/etc/secutor-acme/config.yaml`, а каталога `/etc/secutor-acme/` в
твоём image нет — runc пытается создать его, упирается в read-only
слой `/etc/` (зависит от builder'а / overlay / `--read-only` флага) и
падает с этим сообщением.

Два пути:

1. **Простой (без пересборки image):** монтируй в `/secutor/` —
   каталог точно создан в Dockerfile с владельцем `acme`, всегда
   writable. Все примеры в этом гайде так и сделаны. Соответственно
   поправь и пути внутри `config.yaml` (`certFile`, `keyFile`,
   `caFile`, `keyFile` для TSIG).
2. **Полный:** пересобери образ из исходников (`docker build -t
   secutor-acme:dev acme-server/`) — обновлённый Dockerfile создаёт
   `/etc/secutor-acme/` с правильным владельцем + `chmod 0755`, тогда
   старые пути тоже работают.

Если видишь это сообщение — почти всегда дело в первом пункте: смени
target монтирования на `/secutor/...` (и pull/build свежий образ, на
всякий случай).

### `mtls-required` при подключении с правильным cert'ом

Проверь, что cert+key передаются вместе. С `curl`:

```bash
curl -sk --cert ops-admin.crt --key ops-admin.key https://...
# не curl --cert ops-admin.crt — без --key cert не отправится
```

В TUI: убедись, что выбран правильный источник identity (context cert
должен иметь `type=client`, не `server`).

### `forbidden: requires role operator`

Cert принят, но роль ниже требуемой. Проверь маппинг в `admin.trust`:
fingerprint должен совпадать **точно** (lowercase hex без двоеточий и
без `0x`).

Чтобы узнать, какую роль увидел хаб, дёрни `/info`:

```bash
curl -sk --cert ops-admin.crt --key ops-admin.key \
  https://acme.lan.vpn:8444/admin/v1/info | jq .role
```

### `EPROTO` / `SSL_ERROR_SSL` в `curl`

Серверный admin-cert не загрузился. Проверь права (`0600`, читаемый
acme-процессом) и пути в `config.yaml`. В логе хаба будет
`EACCES: permission denied, open '/secutor/admin-server.key'`.

### TUI: `cert-pin-mismatch`

Серверный admin-cert ротировали, а pin старый. Удали хаб (`D` на
Hubs-экране), добавь заново — TUI спросит новый pin.

### CA stage отвергает кандидата с `root-mismatch`

Staged CA должен chain'иться к **тому же** root, что и сейчас активный.
Это сделано специально: смена trust anchor через rotate-flow не
разрешена (иначе все клиенты сразу теряют доверие). Если нужно
сменить root — это другой сценарий, требующий раздачи нового root
всем клиентам, см. [ca-lifecycle.md](ca-lifecycle.md).

### `nsupdate` не может опубликовать TXT (server-managed DNS)

Прогони вручную внутри контейнера:

```bash
docker compose exec acme nsupdate -k /secutor/tsig.key -v <<EOF
server 10.0.0.53
zone lan.vpn.
update add _acme-challenge.svc.lan.vpn. 30 TXT "test-value"
send
EOF
```

Если падает с `REFUSED` — TSIG-ключ неверный или DNS-сервер не
разрешает update'ы с этого IP. Поправь BIND/PowerDNS-конфиг.

### Хаб упал во время server-managed challenge'а — что с TXT?

На следующем старте `Worker.sweepStalePlacementsOnStartup()` найдёт все
открытые `dns_placements` (где `cleaned_at IS NULL`) и вызовет
`cleanup()` через того же провайдера. Зона очищается автоматически —
ничего делать не нужно.

### `expireOrdersWorker` показывает ордера как `pending`, хотя TTL вышел

Worker крутится каждые 60s. Если в логе видишь, что он не стартует —
проверь, что нет ошибки `migrate0002Admin` в логе старта (старая база
без новых колонок).

## Чек-лист

Прежде чем считать установку готовой:

- [ ] Серверный TLS-cert для admin-listener создан + положен на хаб
      (`0600`).
- [ ] Клиентские admin-cert'ы выпущены, fingerprint'ы собраны
      (sha256 hex, lowercase).
- [ ] Trust-модель выбрана (A: fingerprints, B: cas+subjectMatch, или
      гибрид).
- [ ] Блок `admin:` добавлен в `config.yaml`, файлы смонтированы
      в compose.
- [ ] Порт 8444 проброшен **только** в LAN/VPN-интерфейс (не в
      `0.0.0.0`, если у хаба есть публичный IP).
- [ ] Хаб перезапущен, в логе видно `admin API listening (mTLS)`.
- [ ] Миграции 0002/0003/0004 применились без ошибок (есть строки в
      логе про создание индексов / `ALTER TABLE`).
- [ ] `curl` без cert'а → 401, с admin-cert'ом → 200.
- [ ] Роль из `/admin/v1/info` совпадает с ожидаемой.
- [ ] В TUI на админской машине добавлен хаб, fingerprint pinned.
- [ ] В TUI: `Verify CA private key` → ✔ зелёная галка (хаб владеет
      ожидаемым CA-приватником).
- [ ] (Если включён server-managed DNS) `nsupdate -k tsig.key` руками
      проходит из контейнера.
- [ ] Записан процесс ротации admin-cert'ов (где лежит current fp,
      кому раздавать новые).

## Связанные документы

- [admin-api.md](admin-api.md) — полный reference по всем endpoint'ам.
- [ca-rotation.md](ca-rotation.md) — stage/promote/rollback CA + reissue
  worker, детали и сценарии.
- [server-managed-dns.md](server-managed-dns.md) — DNS providers,
  конфиг, гарантии cleanup, troubleshooting.
- [usage.md](usage.md) — базовый запуск ACME-сервера (без admin).
- [vpn-setup.md](vpn-setup.md) — WireGuard / Docker сценарии деплоя.
- [troubleshooting.md](troubleshooting.md) — общая диагностика
  ACME-части.
