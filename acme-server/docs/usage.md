# Эксплуатация

Полный сценарий: от подготовки CA до выпуска сертификата на клиенте и автоматического обновления.

## 0. Кому что нужно

| Роль                     | Что устанавливается                                                                                |
|--------------------------|----------------------------------------------------------------------------------------------------|
| **Оператор CA**          | `secutor` (TUI) — создаёт CA, управляет контекстом                                                 |
| **ACME-сервер**          | Docker-образ `secutor-acme` + том с контекстом + Docker secret с паролем                           |
| **Клиент** (сервер app)  | либо встроенный CLI `secutor-acme-client`, либо `certbot`, либо `acme.sh`, либо k8s cert-manager   |
| **Все**                  | root-CA сертификат в системном trust store                                                         |

## 1. Готовим CA в secutor

На машине оператора:

```bash
# из корня репозитория certificate-manager
npm install
npm run build
node dist/cli.js
```

В TUI:
1. `Create context` — задайте имя (например `prod`) и пароль. Пароль будет нужен ACME-серверу.
2. `Create CA` — например `Internal Root CA`, RSA-2048 или ECDSA P-256, срок 10 лет.
3. Из меню `Export root cert` сохраните `ca.pem` — этот файл будете раздавать клиентам.

Контекст лежит в `~/.secutor/contexts/prod/` (внутри `store.enc` + `context.json`).

## 2. Поднимаем ACME-сервер

### 2.1. Один контейнер, локальная разработка

```bash
mkdir -p ./secrets ./acme-data
chmod 700 ./secrets
echo -n 'context-password' > ./secrets/context_password.txt
chmod 600 ./secrets/context_password.txt

docker run -d --name secutor-acme \
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
```

Проверка:

```bash
curl -s http://localhost:8443/directory | jq .
curl -s http://localhost:8443/ca.pem
```

### 2.2. Через docker compose

См. [`docker-compose.example.yaml`](../docker-compose.example.yaml). Полная схема с секретами:

```yaml
services:
  acme:
    image: secutor-acme:0.1.0
    read_only: true
    tmpfs: ["/tmp"]
    ports:
      - "8443:8443"
    volumes:
      - ${HOME}/.secutor/contexts/prod:/secutor/context:ro
      - secutor-acme-data:/var/lib/secutor-acme
      - ./config.yaml:/etc/secutor-acme/config.yaml:ro
    environment:
      SECUTOR_CONTEXT_DIR: /secutor/context
      SECUTOR_CONTEXT_PASSWORD_FILE: /run/secrets/context_password
      SECUTOR_ACME_DB: /var/lib/secutor-acme/acme.db
      SECUTOR_ACME_CONFIG: /etc/secutor-acme/config.yaml
      SECUTOR_ACME_BASE_URL: https://acme.lan/
      SECUTOR_ACME_LISTEN: 0.0.0.0:8443
    secrets: [context_password]
    restart: unless-stopped

secrets:
  context_password:
    file: ./secrets/context_password.txt

volumes:
  secutor-acme-data:
```

### 2.3. Какой CA будет подписывать

Если в контексте один CA — он и подписывает, выбирать нечего.

Если несколько (например, `Root` + `Intermediate`):

- Без явного указания берётся **первый по `id`** в контексте — это тот, который вы создали раньше всех. Обычно это корень.
- Чтобы подписывать intermediate'ом, укажите его имя:
  ```yaml
  caCertName: intermediate-ca
  ```
  или env: `SECUTOR_CA_CERT_NAME=intermediate-ca`.

При старте сервер пишет в лог, кого выбрал и какой глубины цепочка:

```
secutor-acme ready — signing as "intermediate-ca" (CN=Internal Intermediate), 1 intermediate(s) in chain
```

Что отдаётся клиентам:

| Endpoint        | Содержимое                                                                                |
|-----------------|-------------------------------------------------------------------------------------------|
| `/cert/:id`     | leaf + signing-CA + … (root исключён — конвенция ACME RFC 8555 §7.4.2)                    |
| `/chain.pem`    | то же что отдаётся после leaf'а: signing-CA + промежуточные (root исключён)               |
| `/ca.pem`       | **корень** (всегда верхушка цепочки) — для раздачи в trust store клиентам                 |

Если signing CA = root, то `/chain.pem` отдаст сам root (запасной вариант), и в `/cert/:id` после leaf'а будет тот же root — единственное полезное содержимое. Клиент при этом обычно уже доверяет корню локально.

### 2.4. Конфиг

`config.yaml` (опционален — всё переопределяется env):

```yaml
baseUrl: https://acme.lan/
caCertName: null           # null = первый ca в контексте; либо имя
leafValidityDays: 90
nonceTtlSec: 600
orderTtlSec: 604800

challenges:
  dns01: true
  http01: false            # для LAN/VPN — выключить, всё равно толку нет

resolvers:
  - zones: ["lan", "vpn"]
    servers: ["10.0.0.53"]
  - zones: ["*"]
    servers: ["1.1.1.1", "8.8.8.8"]

# Опционально: разрешать только перечисленные имена/зоны
# allowList:
#   dnsPatterns: ["*.lan", "*.vpn"]
```

**resolvers** — критично. ACME-сервер сам резолвит `_acme-challenge.<имя>`. Для внутренних зон укажите ваш внутренний DNS. См. [vpn-setup.md](vpn-setup.md).

## 3. Раздаём root-CA клиентам

Все клиенты должны доверять вашему CA, иначе HTTPS-сертификаты, выпущенные через ACME, не будут считаться валидными.

### Linux (Debian/Ubuntu)

```bash
sudo cp ca.pem /usr/local/share/ca-certificates/secutor-root.crt
sudo update-ca-certificates
# проверка: openssl s_client -connect host.lan:443 -CAfile /etc/ssl/certs/ca-certificates.crt
```

### Linux (RHEL/Alma/Fedora)

```bash
sudo cp ca.pem /etc/pki/ca-trust/source/anchors/secutor-root.crt
sudo update-ca-trust extract
```

### Alpine

```bash
sudo cp ca.pem /usr/local/share/ca-certificates/secutor-root.crt
sudo update-ca-certificates
```

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.pem
```

### Windows

```powershell
Import-Certificate -FilePath ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

### Через Ansible

```yaml
- name: Trust secutor root
  copy:
    src: ca.pem
    dest: /usr/local/share/ca-certificates/secutor-root.crt
    mode: '0644'
  notify: update-ca-certificates
```

### В Docker-образах

```dockerfile
COPY ca.pem /usr/local/share/ca-certificates/secutor-root.crt
RUN update-ca-certificates
```

## 4. Выпускаем сертификат

### 4.1. Встроенный клиент (mini-certbot)

```bash
npx --package=secutor-acme secutor-acme-client \
  --directory https://acme.lan/directory \
  --domain web.lan \
  --domain api.lan \
  --challenge dns-01 \
  --dns-hook manual \
  --out /etc/secutor-certs/web.lan \
  --account-key /etc/secutor-certs/account.key \
  --algorithm ecdsa-p256
```

Manual-хук распечатает в stdout, какую TXT-запись нужно создать. После размещения и распространения по DNS — нажмите Enter, клиент сам триггернёт challenge и заберёт сертификат.

Выходные файлы: `privkey.pem` + `fullchain.pem` в `--out`.

### 4.2. Встроенный клиент + RFC 2136 (полностью автоматически)

Если ваш внутренний DNS поддерживает динамические апдейты (BIND, PowerDNS, Knot), один из самых чистых способов:

```bash
# nsupdate-keyfile в формате BIND, обычно один раз генерируется:
#   tsig-keygen -a hmac-sha256 acme-update > /etc/secutor-certs/nsupdate.key
# Затем зона в конфиге BIND должна разрешить апдейты по этому ключу.

secutor-acme-client \
  --directory https://acme.lan/directory \
  --domain web.lan \
  --challenge dns-01 \
  --dns-hook rfc2136 \
  --rfc2136-server 10.0.0.53 \
  --rfc2136-zone lan \
  --rfc2136-key /etc/secutor-certs/nsupdate.key \
  --rfc2136-ttl 60 \
  --out /etc/secutor-certs/web.lan \
  --account-key /etc/secutor-certs/account.key
```

### 4.3. Custom hook через script

```bash
secutor-acme-client ... \
  --dns-hook script \
  --dns-hook-script ./my-hook.sh
```

Скрипт получает env-переменные `ACME_ACTION` (`place`/`cleanup`), `ACME_RECORD_NAME`, `ACME_RECORD_VALUE`. Пример для Cloudflare:

```bash
#!/usr/bin/env bash
set -e
case "$ACME_ACTION" in
  place)
    curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
      -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
      -d "{\"type\":\"TXT\",\"name\":\"$ACME_RECORD_NAME\",\"content\":\"$ACME_RECORD_VALUE\",\"ttl\":60}"
    ;;
  cleanup)
    # найдите id записи через GET /dns_records?name=... и удалите
    ;;
esac
```

### 4.4. Certbot

Проверено с certbot 5.6.0. Минимальный запуск:

```bash
certbot certonly \
  --server https://acme.lan/directory \
  --manual --preferred-challenges dns-01 \
  --manual-auth-hook ./auth-hook.sh \
  --manual-cleanup-hook ./cleanup-hook.sh \
  --register-unsafely-without-email --agree-tos --no-eff-email \
  -d web.lan -d www.web.lan
```

`auth-hook.sh` получает `CERTBOT_DOMAIN` и `CERTBOT_VALIDATION`. Для CloudFlare/Route53/etc подойдут готовые certbot-плагины (`certbot-dns-cloudflare`, `certbot-dns-rfc2136`).

### 4.5. acme.sh

```bash
acme.sh --issue --server https://acme.lan/directory \
  --dns dns_nsupdate \
  --dnssleep 30 \
  -d web.lan -d www.web.lan
```

(`dns_nsupdate` ожидает переменные `NSUPDATE_SERVER`, `NSUPDATE_KEY`.)

### 4.6. cert-manager в Kubernetes

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: secutor-acme
spec:
  acme:
    server: https://acme.lan/directory
    privateKeySecretRef:
      name: secutor-acme-account
    solvers:
      - dns01:
          rfc2136:
            nameserver: 10.0.0.53
            tsigKeyName: acme-update
            tsigAlgorithm: HMACSHA256
            tsigSecretSecretRef:
              name: nsupdate-tsig
              key: secret
```

## 5. Автообновление

Сертификаты выпускаются на 90 дней (`leafValidityDays`). Обновлять желательно за 30 дней до истечения.

### Cron + встроенный клиент

```cron
0 3 * * 1  /usr/local/bin/secutor-acme-client --directory https://acme.lan/directory \
           --domain web.lan --dns-hook rfc2136 \
           --rfc2136-server 10.0.0.53 --rfc2136-zone lan \
           --rfc2136-key /etc/secutor-certs/nsupdate.key \
           --out /etc/secutor-certs/web.lan \
           --account-key /etc/secutor-certs/account.key \
           && systemctl reload nginx
```

(Клиент не делает проверку «надо или нет» — он просто выпустит новый. Достаточно гонять раз в неделю.)

### systemd timer

См. [troubleshooting.md](troubleshooting.md#systemd-юнит) — там готовый юнит.

## 6. Отзыв сертификата

Если приватник скомпрометирован:

```bash
# через встроенный клиент — TODO в v0.2; пока вручную через jose:
# или используйте certbot:
certbot revoke --server https://acme.lan/directory \
  --cert-path /etc/secutor-certs/web.lan/fullchain.pem
```

Отозванный серийник появится в CRL: `curl https://acme.lan/crl.pem`.

## 7. Бэкап и восстановление

### Что бэкапить

| Источник                                 | Куда             | Чем                  |
|------------------------------------------|------------------|----------------------|
| `~/.secutor/contexts/prod/`              | offline-хранилище| `tar` + rotation     |
| `secutor-acme-data` volume (`acme.db`)   | nightly          | `sqlite3 .backup`    |
| Пароль контекста                         | Vault/SOPS       | (не на диске)        |

Скрипт для acme.db:

```bash
docker exec secutor-acme sh -c \
  'sqlite3 /var/lib/secutor-acme/acme.db ".backup /var/lib/secutor-acme/acme.bak"'
docker cp secutor-acme:/var/lib/secutor-acme/acme.bak ./backups/acme-$(date +%F).bak
```

### Восстановление

1. Восстановите контекст в `~/.secutor/contexts/prod/`.
2. Положите acme.db обратно в volume.
3. `docker compose up -d acme` — поднимется, прочитает прежнее состояние.

Аккаунты ACME-клиентов сохранятся (привязка по JWK thumbprint), переустановка не понадобится.
