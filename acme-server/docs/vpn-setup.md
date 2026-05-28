# ACME-сервер в WireGuard-сети

Гайд для случая, когда CA и клиенты, выпускающие сертификаты, общаются только через WireGuard. Покрывает топологию, Docker-схему, внутренний DNS, RFC 2136 и доставку trust-якоря.

> **Две схемы размещения сервисов.** Этот документ описывает классический вариант: WG-сервер, ACME и DNS живут **на одной машине (хабе)**. Это самая простая в эксплуатации схема. Если хочется разделить роли — например, держать ACME с приватными ключами CA на отдельной машине, отличной от WG-хаба — смотри [dns-acme-peer.md](dns-acme-peer.md): там DNS и ACME вынесены на отдельный пир VPN. WG-сервер при этом удобно поднимать через [wg-portal-hub.md](wg-portal-hub.md).
>
> Обе схемы используют одну и ту же подсеть `10.10.0.0/24` и одни и те же принципы — отличается только физическое размещение CoreDNS/BIND и ACME-сервера.

## Содержание

- [Топология](#топология)
- [Подсети и DNS](#подсети-и-dns)
- [Поднятие WireGuard](#поднятие-wireguard)
- [Docker и WireGuard вместе](#docker-и-wireguard-вместе)
- [Внутренний DNS](#внутренний-dns)
- [Полный пример](#полный-пример-end-to-end)
- [Гибрид: VPN + публичные хосты](#гибрид-vpn--публичные-хосты)
- [Что проверить перед прод-запуском](#что-проверить-перед-прод-запуском)

---

## Топология

Базовая схема, на которую я буду ссылаться ниже:

```
         ┌───────────────────────────────────┐
         │       hub  (10.10.0.1)            │
         │  ┌──────────────────────────────┐ │
         │  │ wg0       wireguard server   │ │
         │  │ secutor-acme    :8443        │ │
         │  │ bind/coredns    :53          │ │
         │  └──────────────────────────────┘ │
         └─────────────┬─────────────────────┘
                       │ wg0  10.10.0.0/24
       ┌───────────────┼───────────────┐
       │               │               │
  ┌────▼─────┐   ┌─────▼────┐   ┌──────▼────┐
  │ peer1     │  │ peer2     │  │ peer3      │
  │ 10.10.0.10│  │ 10.10.0.11│  │ 10.10.0.12 │
  │ web.lan   │  │ api.lan   │  │ db.lan     │
  └───────────┘  └───────────┘  └────────────┘
```

- **hub** — VPS или сервер, на котором живёт WG-сервер, ACME-сервер и внутренний DNS. На него нацелены клиенты как через VPN, так и иногда через публичный IP (для bootstrap).
- **peer1..N** — серверы приложений. Каждый получает имя в зоне `.lan` и регулярно выпускает свой сертификат.
- DNS-зона `.lan` живёт **только** во внутреннем DNS hub'а — публичные резолверы её не видят, и это правильно.

Все ACME-вызовы идут поверх WG. Сам HTTP внутри WG можно оставить голым — WireGuard уже шифрует. TLS на ACME-эндпоинт нужен, только если он торчит наружу.

## Подсети и DNS

| Сущность               | Адрес                       | Назначение                                  |
|------------------------|-----------------------------|---------------------------------------------|
| WG сеть                | `10.10.0.0/24`              | весь VPN                                    |
| hub WG                 | `10.10.0.1`                 | сервер WG, ACME, DNS                        |
| `acme.lan`             | `10.10.0.1`                 | через внутренний DNS                        |
| `ns1.lan`              | `10.10.0.1`                 | через внутренний DNS                        |
| peer1                  | `10.10.0.10` → `web.lan`    |                                             |
| peer2                  | `10.10.0.11` → `api.lan`    |                                             |

Зачем именные адреса `acme.lan` вместо просто `10.10.0.1`:
1. RFC 8555 предполагает `https://...`, и клиенты типа cert-manager/certbot ругаются на ip-литералы.
2. CA выпускает сертификат именно на `acme.lan` — TLS на ACME-эндпоинте имеет имя совпадающее с URL'ом.

## Поднятие WireGuard

### На hub'е

`/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <HUB_PRIVATE_KEY>

# Опционально: разрешить пирам общаться друг с другом
# (по умолчанию они не видят друг друга — только hub)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = <PEER1_PUBLIC_KEY>
AllowedIPs = 10.10.0.10/32

[Peer]
PublicKey = <PEER2_PUBLIC_KEY>
AllowedIPs = 10.10.0.11/32
```

```bash
sudo systemctl enable --now wg-quick@wg0
```

### На peer'е

`/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.10.0.10/24
PrivateKey = <PEER1_PRIVATE_KEY>
# Используем внутренний DNS, чтобы acme.lan и собственный домен резолвились
DNS = 10.10.0.1

[Peer]
PublicKey = <HUB_PUBLIC_KEY>
Endpoint = hub.example.com:51820
# 10.10.0.0/24 — чтобы маршрутизировался только трафик VPN, не весь интернет
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
```

`DNS = 10.10.0.1` — `wg-quick` пропишет его в `/etc/resolv.conf` пока интерфейс поднят. Если у вас systemd-resolved или resolvconf — будет использовано через них.

## Docker и WireGuard вместе

Самая частая боль: контейнер с приложением живёт на пире, но `docker exec`'нутые в контейнере процессы по умолчанию **не видят** WG-интерфейс хоста. Несколько вариантов в порядке предпочтительности.

### Вариант A — WG живёт на хосте, контейнер использует host networking

Самый простой, обычно достаточно:

```yaml
services:
  app:
    image: my/app
    network_mode: host
```

Контейнер делит сетевой namespace хоста — `10.10.0.10` для него такой же доступный, как для самого хоста. Минусы: нет изоляции портов, контейнер видит все интерфейсы. Для пиров приложений обычно ок.

### Вариант B — Sidecar-контейнер с WG, app использует его сеть

Используем готовый образ `linuxserver/wireguard`. Этот sidecar держит WG-туннель, остальные контейнеры в той же compose-файлике подключаются к его network namespace:

```yaml
services:
  wireguard:
    image: linuxserver/wireguard:latest
    cap_add: [NET_ADMIN, SYS_MODULE]
    sysctls:
      net.ipv4.conf.all.src_valid_mark: 1
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - ./wg-config:/config        # сюда положите wg_confs/wg0.conf
      - /lib/modules:/lib/modules
    ports: []                       # ACME-клиент не слушает извне
    restart: unless-stopped

  app:
    image: my/app
    depends_on: [wireguard]
    network_mode: "service:wireguard"   # делим netns с sidecar
    # никаких ports: и networks: тут — всё через wireguard

  acme-client:
    image: secutor-acme:0.1.0
    depends_on: [wireguard]
    network_mode: "service:wireguard"
    entrypoint: ["node", "dist/client/index.js"]
    command:
      - "--directory"
      - "http://acme.lan/directory"   # HTTP внутри WG — см. dns-acme-peer.md / deployment.md
      - "--domain"
      - "web.lan"
      - "--challenge"
      - "dns-01"
      - "--dns-hook"
      - "rfc2136"
      - "--rfc2136-server"
      - "10.10.0.1"
      - "--rfc2136-zone"
      - "lan"
      - "--rfc2136-key"
      - "/secrets/nsupdate.key"
      - "--out"
      - "/certs"
      - "--account-key"
      - "/state/account.key"
    volumes:
      - certs:/certs
      - acme-state:/state
      - ./secrets/nsupdate.key:/secrets/nsupdate.key:ro

volumes:
  certs:
  acme-state:
```

`network_mode: "service:wireguard"` — ключевая фишка. `app` и `acme-client` думают, что они на хосте `10.10.0.10` (адресе WG-пира). DNS внутри них берётся из `/etc/resolv.conf` sidecar'а — обычно его задаёт `linuxserver/wireguard` из WG-конфига, и он будет указывать на `10.10.0.1`. Это и нужно для резолвинга `.lan`.

### Вариант C — WG как named docker network с помощью `network-namespace`

Тонкий, но иногда нужен. Создать на хосте WG-интерфейс через `wg-quick`, потом сделать docker-сеть через `pipework`/`macvlan`/CNI с этим интерфейсом. Сложнее и хрупче, не рекомендую без явной причины.

## Внутренний DNS

ACME-сервер сам ходит за TXT-записями, значит DNS должен:
1. Знать зону `.lan` (или какую вы выбрали).
2. Разрешать ACME-клиентам делать в неё динамические апдейты (RFC 2136 / nsupdate) — иначе клиентам придётся ставить TXT руками.
3. Слушать на адресе hub'а в WG-сети — `10.10.0.1`.

Я опишу вариант с **BIND 9**, потому что он лучше всех документирован и хорошо работает с certbot-dns-rfc2136 и acme.sh.

### BIND 9 на hub'е, в Docker

```yaml
services:
  bind:
    image: internetsystemsconsortium/bind9:9.18
    network_mode: host                     # чтобы слушать на 10.10.0.1:53
    volumes:
      - ./bind/named.conf:/etc/bind/named.conf:ro
      - ./bind/zones:/etc/bind/zones
      - ./bind/keys:/etc/bind/keys:ro
    restart: unless-stopped
```

`bind/named.conf`:

```conf
options {
    directory "/var/cache/bind";
    listen-on { 127.0.0.1; 10.10.0.1; };
    listen-on-v6 { none; };
    allow-query { 127.0.0.0/8; 10.10.0.0/24; };
    recursion yes;
    forwarders { 1.1.1.1; 8.8.8.8; };
    dnssec-validation no;     # для внутренней зоны проще без
};

include "/etc/bind/keys/acme-update.key";

zone "lan" {
    type master;
    file "/etc/bind/zones/db.lan";
    allow-update { key "acme-update"; };
    journal "/etc/bind/zones/db.lan.jnl";
};
```

`bind/zones/db.lan`:

```
$TTL 300
@   IN  SOA  ns1.lan. admin.lan. (
            2026010101 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            300 )      ; minimum
    IN  NS    ns1.lan.

ns1   IN  A   10.10.0.1
acme  IN  A   10.10.0.1
web   IN  A   10.10.0.10
api   IN  A   10.10.0.11
db    IN  A   10.10.0.12
```

### Генерация TSIG-ключа

```bash
docker run --rm -v $(pwd)/bind/keys:/keys \
  internetsystemsconsortium/bind9:9.18 \
  tsig-keygen -a hmac-sha256 acme-update > bind/keys/acme-update.key
chmod 600 bind/keys/acme-update.key
```

В файле получится:

```
key "acme-update" {
    algorithm hmac-sha256;
    secret "BASE64ENCODED==";
};
```

**Этот файл — ваш секрет.** Раздавайте только тем клиентам, кому разрешено писать в зону. Хранить как Docker secret, в Vault, или просто `chmod 600`.

Любой клиент с этим ключом может писать TXT в `.lan`. Хотите гранулярности — выделите subzone (`_acme-challenge.lan`) и разрешите обновления только там.

### Проверка вручную

С пира:

```bash
nsupdate -k /path/to/acme-update.key -v <<EOF
server 10.10.0.1
zone lan.
update add _acme-challenge.web.lan. 60 TXT "test-value"
send
EOF

dig @10.10.0.1 _acme-challenge.web.lan TXT +short
# "test-value"
```

Если последний вывод пуст — лезьте смотреть `docker logs bind` и `named.run`. Чаще всего: либо TSIG не подгрузился, либо zone-файл не writable.

## Полный пример end-to-end

На hub'е (`10.10.0.1`):

```yaml
# docker-compose.yml на hub
services:
  bind:
    image: internetsystemsconsortium/bind9:9.18
    network_mode: host
    volumes:
      - ./bind/named.conf:/etc/bind/named.conf:ro
      - ./bind/zones:/etc/bind/zones
      - ./bind/keys:/etc/bind/keys:ro
    restart: unless-stopped

  acme:
    image: secutor-acme:0.1.0
    read_only: true
    tmpfs: ["/tmp"]
    network_mode: host          # ACME слушает на 10.10.0.1:8443
    volumes:
      - ${HOME}/.secutor/contexts/prod:/secutor/context:ro
      - acme-data:/var/lib/secutor-acme
      - ./config.yaml:/etc/secutor-acme/config.yaml:ro
    environment:
      SECUTOR_CONTEXT_DIR: /secutor/context
      SECUTOR_CONTEXT_PASSWORD_FILE: /run/secrets/context_password
      SECUTOR_ACME_DB: /var/lib/secutor-acme/acme.db
      SECUTOR_ACME_CONFIG: /etc/secutor-acme/config.yaml
      SECUTOR_ACME_BASE_URL: http://acme.lan:8443/
      SECUTOR_ACME_LISTEN: 10.10.0.1:8443
    secrets: [context_password]
    restart: unless-stopped

secrets:
  context_password:
    file: ./secrets/context_password.txt

volumes:
  acme-data:
```

`config.yaml` на hub'е:

```yaml
baseUrl: http://acme.lan:8443/
contextDir: /secutor/context
contextPasswordFile: /run/secrets/context_password
stateDb: /var/lib/secutor-acme/acme.db
leafValidityDays: 90

challenges:
  dns01: true
  http01: false

resolvers:
  - zones: ["lan"]
    servers: ["10.10.0.1"]
  - zones: ["*"]
    servers: ["1.1.1.1"]

allowList:
  dnsPatterns: ["*.lan"]    # запрещаем выпускать на что попало
```

На пире (`10.10.0.10`, домен `web.lan`):

```bash
# 1. WG поднят, DNS = 10.10.0.1
# 2. Скачиваем root CA и доверяем ему
curl -sS http://acme.lan:8443/ca.pem | sudo tee /usr/local/share/ca-certificates/secutor-root.crt > /dev/null
sudo update-ca-certificates

# 3. Берём nsupdate-ключ из vault'а (TSIG)
sudo install -m 600 /tmp/acme-update.key /etc/secutor-certs/nsupdate.key

# 4. Выпускаем
docker run --rm \
  -v /etc/secutor-certs:/certs \
  -v /etc/secutor-certs/nsupdate.key:/secrets/nsupdate.key:ro \
  --network host \
  secutor-acme:0.1.0 \
  node dist/client/index.js \
    --directory http://acme.lan:8443/directory \
    --domain web.lan \
    --challenge dns-01 \
    --dns-hook rfc2136 \
    --rfc2136-server 10.10.0.1 \
    --rfc2136-zone lan \
    --rfc2136-key /secrets/nsupdate.key \
    --out /certs/web.lan \
    --account-key /certs/account.key \
    --algorithm ecdsa-p256
```

Результат: `/etc/secutor-certs/web.lan/{privkey.pem,fullchain.pem,csr.pem}` на пире. Перезагружаем nginx — он отдаёт `https://web.lan/` с легитимным (для членов VPN) сертификатом.

### Что попало в WG, что нет

- ACME-трафик (`acme.lan:8443`): peer → hub через WG.
- DNS-запросы клиента (`_acme-challenge.web.lan`): peer → hub:53 через WG (если в `wg0.conf` указан `DNS = 10.10.0.1`).
- ACME-сервер делает резолв `_acme-challenge.web.lan`: hub → localhost:53 (BIND слушает и на 127.0.0.1).
- TXT-апдейты от клиента: peer → hub:53 (nsupdate-протокол поверх WG).

Никакой трафик не выходит в публичный интернет, кроме самого WG-handshake'а на 51820/udp.

## Гибрид: VPN + публичные хосты

Иногда часть серверов в WG, а часть — на белых IP, и нужно выпускать сертификаты на обе категории.

Два подхода:

### A. Один ACME-сервер на белом IP, всем доступен

ACME-сервер слушает на публичном TCP, с настоящим TLS (Let's Encrypt'овский cert на сам ACME-эндпоинт; или внутренний для членов VPN). HTTP-01 включен для публичных доменов, DNS-01 — для внутренних. Конфиг резолверов:

```yaml
resolvers:
  - zones: ["lan"]
    servers: ["10.10.0.1"]     # внутренний DNS через WG
  - zones: ["*"]
    servers: ["1.1.1.1"]
```

Сам ACME-сервер должен быть и в WG-сети (через wg на хосте), и слушать на публичном порту. Для WG-доступа к внутреннему DNS — нужен WG-туннель на машине с ACME-сервером.

### B. Два ACME-сервера

`acme.public.example.com` (с HTTP-01, без `*.lan`) и `acme.lan` (с DNS-01, с allow-list `*.lan`). Каждый клиент знает, к какому идти. Проще, чище, не пересекаются.

## Что проверить перед прод-запуском

- [ ] CA-ключ сохранён вне ACME-сервера. ACME-сервер монтирует контекст read-only.
- [ ] Пароль контекста — в Docker secret или Vault, не в env.
- [ ] `read_only: true` + `tmpfs: /tmp` на acme-контейнере.
- [ ] BIND слушает только на 10.10.0.1 и 127.0.0.1, не на публичных интерфейсах.
- [ ] TSIG-ключ имеет `chmod 600` и принадлежит сервис-аккаунту.
- [ ] У BIND отключен AXFR наружу (`allow-transfer { none; };`).
- [ ] WG-handshake требует actual private keys, не keys из примеров выше.
- [ ] `allowList.dnsPatterns` в config.yaml не пуст — иначе любой с аккаунтом выпустит cert на любое имя.
- [ ] CRL endpoint доступен (`curl http://acme.lan:8443/crl.pem | openssl crl -text -noout`).
- [ ] Бэкап `~/.secutor/contexts/prod/` лежит offline и не в одном datacenter с hub'ом.
- [ ] У клиентов крон-задача на обновление, и `systemctl reload <service>` после обновления.
- [ ] При компрометации одного peer'а его аккаунт ACME можно деактивировать (TODO в текущей версии — пока вручную через SQL: `UPDATE accounts SET status='deactivated' WHERE id=?` в `acme.db`).

---

## Связанные документы

- [ca-lifecycle.md](ca-lifecycle.md) — создание root + intermediate CA, бэкапы, доставка trust anchor, ротация. **Обязательно прочитать перед прод-запуском.**
- [wg-portal-hub.md](wg-portal-hub.md) — подробная установка WG-хаба через wg-portal (UI, REST API, OIDC/LDAP). Заменяет ручную настройку WG-сервера, описанную в разделе [«Поднятие WireGuard»](#поднятие-wireguard).
- [dns-acme-peer.md](dns-acme-peer.md) — альтернативная схема, где DNS и ACME-сервер вынесены на отдельный пир VPN. Используй, если хочешь разделить хаб и сервисы.
- [wg-interconnect.md](wg-interconnect.md) — детальный разбор топологий: hub-and-spoke, site-to-site, full mesh, объединение нескольких WG-сетей. Полезно при росте инфраструктуры.
- [wg-traefik-client-setup.md](wg-traefik-client-setup.md) — клиентская сторона: WG-клиент + Traefik как реверс-прокси для VPN-трафика, паттерн `network_mode: service:wg`.
- [deployment.md](deployment.md) — общий деплой secutor-acme: тома, секреты, env-переменные, `read_only`.
- [usage.md](usage.md) — как пользоваться ACME-сервером с клиента, выпуск сертификатов.
