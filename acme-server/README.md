# secutor-acme

ACME (RFC 8555) сервер поверх CA, управляемого `secutor`. Совместим с certbot, acme.sh, cert-manager и Traefik (встроенный ACME-резолвер).

**v0.1.0**: rabotaem end-to-end. RFC 8555 (DNS-01, HTTP-01), CRL, отзыв, RFC 2136 client-hook. Подтверждено E2E + реальным certbot 5.6.0.

## С чего начать

| Если вы…                                       | Читать                                                                |
|------------------------------------------------|-----------------------------------------------------------------------|
| хотите понять, как оно устроено                | [docs/architecture.md](docs/architecture.md)                          |
| собираетесь развернуть и пользоваться          | **[docs/usage.md](docs/usage.md)** ← основной гайд                    |
| ставите в WireGuard / Docker / LAN-сценарий    | **[docs/vpn-setup.md](docs/vpn-setup.md)** ← VPN-сетап от и до        |
| хотите **поднять администрирование** на хабе   | **[docs/admin-setup.md](docs/admin-setup.md)** ← пошаговый setup-гайд |
| хотите дёргать admin API из своих скриптов     | **[docs/admin-api.md](docs/admin-api.md)** ← admin (mTLS) reference   |
| планируете ротацию CA или массовый перевыпуск  | [docs/ca-rotation.md](docs/ca-rotation.md)                            |
| хотите, чтобы хаб сам публиковал DNS-01 TXT    | [docs/server-managed-dns.md](docs/server-managed-dns.md)              |
| что-то не работает                             | [docs/troubleshooting.md](docs/troubleshooting.md)                    |
| хотите знать про секреты / mounts / тома       | [docs/deployment.md](docs/deployment.md)                              |
| ковыряетесь в БД ACME-стейта                   | [docs/schema.md](docs/schema.md)                                      |

## Что нового в 0.2 (admin/rotate/auto-DNS)

Поверх обычного RFC 8555 поднимается опциональный второй слой:

- **Admin API (mTLS)** на отдельном порту — `/admin/v1/*`. Инвентаризация
  сертификатов, отзыв (operator), бан аккаунтов с каскадным revoke (owner),
  статистика по ордерам, аудит-лог, метрики Prometheus, admin-issue
  (выпуск в обход challenge'ей). Trust для admin-клиентов настраивается
  отдельно от ACME-CA: список fingerprint'ов и/или независимых CA с
  subjectMatch.
- **CA rotation** через admin API: stage → promote (atomic in-RAM swap) →
  rollback (в окне). Плюс background reissue job, который пересigning'ит
  все валидные leaf'ы под новый ключ.
- **Server-managed DNS-01** — клиент может попросить хаб самостоятельно
  опубликовать TXT-запись через сконфигурированного провайдера
  (rfc2136 / script / in-memory для тестов).
- **ARI** (`GET /renewalInfo/:id`) — подсказка о renewal-окне для
  совместимых клиентов.

## Минимальная демонстрация (полный E2E без сети)

```bash
cd acme-server
npm install
npx tsx test/e2e.ts
```

Поднимает свой ACME-сервер на временном CA, прогоняет клиент (account → order → DNS-01 → CSR → выпуск → отзыв → CRL), проверяет цепочку через `openssl verify`. ≈3 секунды.

## Минимальный реальный запуск

```bash
docker run -d --name acme \
  -p 8443:8443 \
  -v "$HOME/.secutor/contexts/prod:/secutor/context:ro" \
  -v "$(pwd)/acme-data:/var/lib/secutor-acme" \
  -v "$(pwd)/secrets/context_password.txt:/run/secrets/context_password:ro" \
  -e SECUTOR_CONTEXT_DIR=/secutor/context \
  -e SECUTOR_CONTEXT_PASSWORD_FILE=/run/secrets/context_password \
  -e SECUTOR_ACME_DB=/var/lib/secutor-acme/acme.db \
  -e SECUTOR_ACME_BASE_URL=http://localhost:8443/ \
  -e SECUTOR_ACME_LISTEN=0.0.0.0:8443 \
  secutor-acme:0.1.0

curl http://localhost:8443/directory | jq .
curl http://localhost:8443/ca.pem
```

Полные сценарии (включая `docker-compose`, secrets, конфиг для VPN) — в [docs/usage.md](docs/usage.md) и [docs/vpn-setup.md](docs/vpn-setup.md).

## Минимальный выпуск с клиента

```bash
npx tsx src/client/index.ts \
  --directory http://localhost:8443/directory \
  --domain web.lan \
  --challenge dns-01 \
  --dns-hook manual \
  --out ./certs/web.lan \
  --account-key ./account.key \
  --algorithm ecdsa-p256
```

Поддерживаются также `certbot`, `acme.sh`, cert-manager — см. [docs/usage.md §4](docs/usage.md#4-выпускаем-сертификат).

## Архитектура одной картинкой

```
                            HTTP/JSON
   ACME client ─────────────────────────────────► secutor-acme
   (certbot / встроенный / cert-manager)             │
                                                     │
                  ┌─────────────────────────┬────────┴────────┐
                  ▼                         ▼                 ▼
               Resolver                  CSR signer        ACME state
              per-zone DNS              (CA in RAM)      (SQLite, WAL)
                  │                         │
                  │                         ▼
          internal/public                CA store
              DNS                       (mounted RO
                                         from secutor
                                         context dir)
```

Подписной ключ CA расшифровывается из секутор-контекста при старте и держится в памяти. На диске сервер ничего секретного не хранит.

## Что в репозитории

```
acme-server/
├── Dockerfile, docker-compose.example.yaml, config.example.yaml
├── README.md
├── docs/
│   ├── architecture.md     дизайн, потоки challenge, режимы авторизации
│   ├── schema.md           таблицы acme.db (accounts, orders, challenges, …)
│   ├── deployment.md       тома, секреты, конфиг
│   ├── usage.md            полный практический гайд
│   ├── vpn-setup.md        WireGuard/Docker сценарии
│   └── troubleshooting.md  диагностика, SQL, шпаргалка эндпоинтов
├── src/
│   ├── server/             ACME-сервер
│   └── client/             встроенный клиент (mini-certbot)
└── test/
    ├── e2e.ts              E2E (наш клиент, in-process DNS)
    └── certbot/            интеграционный тест с реальным certbot
```
