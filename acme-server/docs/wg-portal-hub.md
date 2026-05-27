# wg-portal на хабе VPN

Подробный сквозной гайд: как поднять [wg-portal](https://github.com/h44z/wg-portal) v2 на хабе VPN, настроить его под нашу схему (`10.10.0.0/24`, внутренний DNS на `10.10.0.1`, домены `*.lan.vpn`), создать первый интерфейс, добавить обычных клиентов и site-to-site пира, прикрыть админку HTTPS-ом и автоматизировать через API.

Расписано подробно, без пропусков. Если ты впервые трогаешь WireGuard или Docker — иди по шагам сверху вниз, всё получится.

## Содержание

- [Зачем wg-portal, а не альтернативы](#зачем-wg-portal-а-не-альтернативы)
- [Цель и предусловия](#цель-и-предусловия)
- [Что в итоге получится](#что-в-итоге-получится)
- [Архитектура](#архитектура)
- [Шаг 0. Подготовка хоста](#шаг-0-подготовка-хоста)
- [Шаг 1. Структура каталога](#шаг-1-структура-каталога)
- [Шаг 2. docker-compose.yml](#шаг-2-docker-composeyml)
- [Шаг 3. config/config.yaml](#шаг-3-configconfigyaml)
- [Шаг 4. Первый запуск](#шаг-4-первый-запуск)
- [Шаг 5. Создание интерфейса wg0](#шаг-5-создание-интерфейса-wg0)
- [Шаг 6. Добавление обычного клиента (hub-and-spoke)](#шаг-6-добавление-обычного-клиента-hub-and-spoke)
- [Шаг 7. Добавление site-to-site клиента](#шаг-7-добавление-site-to-site-клиента)
- [Шаг 8. HTTPS для UI через хостовой nginx](#шаг-8-https-для-ui-через-хостовой-nginx)
- [Шаг 9. Аутентификация через OIDC/LDAP](#шаг-9-аутентификация-через-oidcldap)
- [Шаг 10. REST API и автоматизация](#шаг-10-rest-api-и-автоматизация)
- [Бэкапы](#бэкапы)
- [Обновление wg-portal](#обновление-wg-portal)
- [Мониторинг](#мониторинг)
- [Типичные грабли](#типичные-грабли)
- [Чек-лист перед уходом в прод](#чек-лист-перед-уходом-в-прод)

---

## Зачем wg-portal, а не альтернативы

Короткое сравнение, чтобы было ясно, на чём остановились:

| Решение | Когда брать | Когда не брать |
|---|---|---|
| **wg-portal** | До ~500 пиров, нужен web-UI, site-to-site, несколько `wgX`, LDAP/OIDC, REST API | Если совсем нет пиров (1-2 клиента — голый wg-quick проще) |
| **wg-easy** | До ~30 пиров, чистый hub-and-spoke без site-to-site | Если нужен site-to-site через UI или несколько интерфейсов |
| **Firezone v1** | Корпоративный сценарий с ZTNA-политиками, аудитом, SSO для тысяч пользователей | Под маленькую/среднюю инсталляцию — оверкилл |
| **Голый wg-quick** | GitOps-культура, конфиги в репозитории, минимум абстракций | Когда клиентов больше 10-15 — руками управлять больно |

Для типичного ACME-сервера в LAN VPN с разнородными клиентами (часть просто пользователи с ноутбуков, часть — офисные роутеры с сайтом за собой) **wg-portal — оптимум**.

---

## Цель и предусловия

**Цель**: на хосте, который выступает хабом VPN, поднять wg-portal, который:
- Создаёт и поддерживает WG-интерфейс `wg0` с подсетью `10.10.0.0/24`.
- Даёт web-UI для управления пирами.
- Не теряет ручные правки `AllowedIPs` (это и есть его фишка по сравнению с wg-easy).
- Доступен админам через `https://wg.lan.vpn`.

**Что должно быть готово до начала**:

1. На хосте установлен Linux (Ubuntu 22.04+, Debian 12, любой современный) и работает Docker с docker-compose v2 (`docker compose version` отвечает).
2. На хосте есть **публичный IP** или проброс UDP-порта 51820 — клиенты должны иметь возможность достучаться.
3. Ядро поддерживает WireGuard (с Linux 5.6+ это in-tree, ничего ставить не надо). Проверка: `modprobe wireguard && lsmod | grep wireguard`.
4. На хабе должен быть **DNS-сервер** на `10.10.0.1:53`, который резолвит:
   - `*.lan.vpn` — внутренние сервисы,
   - `wg.lan.vpn` — указывает на адрес хаба в VPN (или на его LAN-IP, смотря откуда админ ходит).
   Если DNS-сервера пока нет — см. [vpn-setup.md](vpn-setup.md), раздел про внутренний DNS.
5. Желательно — внутренний CA (acme-сервер), чтобы выдать TLS-сертификат для `wg.lan.vpn`.

---

## Что в итоге получится

После всех шагов:

- На хабе работает контейнер `wg-portal`, поднимающий WG-интерфейс `wg0` с адресом `10.10.0.1/24`.
- UI доступен на `https://wg.lan.vpn` (через хостовой nginx с TLS).
- Через UI можно добавлять/удалять пиров, видеть статистику handshake, скачивать конфиги и QR-коды.
- Один пир — обычный клиент (`peerA`, `10.10.0.2`).
- Один пир — site-to-site роутер офиса (`peerB`, `10.10.0.3`, за ним сеть `192.168.20.0/24`).
- Конфиг wg-portal лежит в git, бэкап SQLite — в крон, обновление образа — через `docker compose pull`.

---

## Архитектура

```
                    Интернет
                        │
                        │ UDP 51820
                        ▼
   ┌──────────────────────────────────────────┐
   │  Hub (10.10.0.1, public IP)               │
   │                                            │
   │  ┌────────────────────────────────────┐    │
   │  │ wg-portal (Docker, host network)    │    │
   │  │  - управляет интерфейсом wg0        │    │
   │  │  - SQLite в ./data/sqlite.db        │    │
   │  │  - UI на 127.0.0.1:8888             │    │
   │  └────────────────────────────────────┘    │
   │                                            │
   │  ┌────────────────────────────────────┐    │
   │  │ wg0 (10.10.0.1/24)                   │    │
   │  │ ├── peer A   10.10.0.2  (юзер)        │    │
   │  │ ├── peer B   10.10.0.3  (офисный gw)  │    │
   │  │ │            + 192.168.20.0/24         │    │
   │  │ └── peer C   10.10.0.4  (сервер)      │    │
   │  └────────────────────────────────────┘    │
   │                                            │
   │  ┌────────────────────────────────────┐    │
   │  │ nginx (host, 443)                    │    │
   │  │  └─ wg.lan.vpn → 127.0.0.1:8888      │    │
   │  └────────────────────────────────────┘    │
   │                                            │
   │  ┌────────────────────────────────────┐    │
   │  │ DNS server (CoreDNS/BIND, :53)       │    │
   │  │  - *.lan.vpn                          │    │
   │  └────────────────────────────────────┘    │
   │                                            │
   │  ┌────────────────────────────────────┐    │
   │  │ ACME server (acme.lan.vpn:8443)      │    │
   │  └────────────────────────────────────┘    │
   └──────────────────────────────────────────┘
```

Ключевые решения:

- **`network_mode: host`** — wg-portal сам через `wg`/`ip` управляет интерфейсами в host network namespace. Это самый простой и предсказуемый режим. `sudo wg show` на хосте видит то же, что и UI.
- **UI слушает только на 127.0.0.1** — публично торчит nginx с TLS. Защита от случайного выставления админки в интернет.
- **SQLite, а не Postgres** — для нашего масштаба (десятки-сотни пиров) SQLite более чем достаточно, не плодит лишних сервисов.

---

## Шаг 0. Подготовка хоста

### 0.1. Включить ip_forward навсегда

```bash
sudo tee /etc/sysctl.d/99-wg.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.src_valid_mark = 1
EOF
sudo sysctl -p /etc/sysctl.d/99-wg.conf
```

Проверка:
```bash
sysctl net.ipv4.ip_forward    # должно быть = 1
```

### 0.2. Открыть UDP 51820

Зависит от того, как настроен фаервол. Для `ufw`:
```bash
sudo ufw allow 51820/udp
```

Для `firewalld`:
```bash
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --reload
```

Для облачного хоста — открыть в security group / firewall провайдера.

### 0.3. Убедиться, что WireGuard работает

```bash
sudo modprobe wireguard
lsmod | grep wireguard
```

Если модуль есть — отлично. Если ядро старое и модуля нет — поставь пакет:
```bash
sudo apt install wireguard-tools wireguard
```

### 0.4. Убедиться, что 51820 свободен

```bash
sudo ss -ulnp | grep 51820
```

Пусто = свободен. Если что-то занято — найди и останови (возможно, на хосте уже был запущен `wg-quick@wg0`):
```bash
sudo systemctl disable --now wg-quick@wg0
```

### 0.5. Убедиться, что порт 8888 свободен

```bash
sudo ss -tlnp | grep 8888
```

---

## Шаг 1. Структура каталога

```bash
mkdir -p ~/wg-portal/{config,data}
cd ~/wg-portal
```

Финальная структура:

```
~/wg-portal/
├── docker-compose.yml
├── config/
│   └── config.yaml        # главный конфиг wg-portal
└── data/                  # создастся при первом запуске
    ├── sqlite.db          # БД с пирами, ключами, аудитом
    └── wireguard/         # сгенерированные wg-quick конфиги
```

Права:
```bash
chmod 700 ~/wg-portal/data ~/wg-portal/config
```

---

## Шаг 2. docker-compose.yml

```yaml
services:
  wg-portal:
    image: ghcr.io/h44z/wg-portal:v2
    container_name: wg-portal
    restart: unless-stopped

    # Главный режим: используем сетевой namespace хоста.
    # wg-portal сам создаёт интерфейсы wgX на хосте через ip/wg.
    network_mode: host

    cap_add:
      - NET_ADMIN

    sysctls:
      net.ipv4.ip_forward: 1
      net.ipv4.conf.all.src_valid_mark: 1

    environment:
      - TZ=Europe/Moscow

    volumes:
      - ./config/config.yaml:/app/config/config.yaml:ro
      - ./data:/app/data
      # модули ядра — нужны, если wireguard грузится как модуль (на новых ядрах не критично)
      - /lib/modules:/lib/modules:ro

    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8888/api/v0/now"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
```

### Построчный разбор

- **`image: ghcr.io/h44z/wg-portal:v2`** — лучше зафиксировать на конкретной мажорной версии, чем брать `latest`. Сломанное обновление при `docker compose pull` — болезненный сценарий. На прод желательно ещё и пин по minor (`:v2.0.3`).
- **`network_mode: host`** — самый стабильный режим. Альтернатива (bridge с пробросом портов) описана внизу.
- **`cap_add: NET_ADMIN`** — без этого нельзя создавать сетевые интерфейсы.
- **`sysctls`** — даже если на хосте уже выставлено через `/etc/sysctl.d/`, дублируем в compose, чтобы конфиг был самодостаточным.
- **`./config/config.yaml:...:ro`** — конфиг read-only, чтобы случайно не записался изнутри контейнера. wg-portal этого не делает, но привычка хорошая.
- **`./data:/app/data`** — read-write, тут БД и сгенерированные `wg-quick` файлы.
- **`/lib/modules:/lib/modules:ro`** — нужно только если ядро HostOS грузит wireguard как модуль (а не in-tree). Безопасно держать всегда.
- **`healthcheck`** — пингуем эндпоинт `/api/v0/now`, который должен отдавать текущее время. Если не отвечает — что-то не так.

### Альтернатива: bridge с пробросом портов

Если по каким-то причинам `network_mode: host` не подходит (например, на хосте уже занят 8888):

```yaml
services:
  wg-portal:
    image: ghcr.io/h44z/wg-portal:v2
    cap_add: [NET_ADMIN, SYS_MODULE]
    sysctls:
      net.ipv4.ip_forward: 1
      net.ipv4.conf.all.src_valid_mark: 1
    # environment:  Если нужно поменять порт на нестандартный
    #   - WG_PORTAL_ADVANCED_START_LISTEN_PORT=55555
    ports:
      - "51820:51820/udp"
      - "127.0.0.1:8888:8888/tcp"   # UI только на localhost
    volumes:
      - ./config/config.yaml:/app/config/config.yaml:ro
      - ./data:/app/data
      - /lib/modules:/lib/modules:ro
    restart: unless-stopped
```

Минус: `sudo wg show` на хосте **не увидит** интерфейс, потому что он в namespace контейнера. Дебажить надо через `docker exec wg-portal wg show`. Большинству пользователей удобнее `host`.

---

## Шаг 3. config/config.yaml

Это самая важная часть. Разберу по блокам.

### Полный пример

```yaml
core:
  admin_user: admin@example.com
  admin_password: ChangeMe_AtFirstLogin_12345
  editable_keys: true
  create_default_peer: false
  create_default_peer_on_creation: false
  self_provisioning_allowed: false
  default_language: en

advanced:
  config_storage_path: /app/data/wireguard
  expiry_check_interval: 15m
  rule_prio_offset: 20000
  route_table_offset: 20000
  api_admin_only: true

web:
  request_logging: false
  external_url: https://wg.lan.vpn
  listening_address: "127.0.0.1:8888"
  session_identifier: wgportal_session
  session_secret: REPLACE_WITH_LONG_RANDOM_STRING_AT_LEAST_32_CHARS
  csrf_secret: ANOTHER_LONG_RANDOM_STRING_AT_LEAST_32_CHARS
  site_title: "VPN Hub"
  site_company_name: "Internal Networks"

database:
  type: sqlite
  dsn: /app/data/sqlite.db

statistics:
  use_ping_checks: true
  ping_check_workers: 10
  ping_unprivileged: false
  ping_check_interval: 1m
  data_collection_interval: 1m
  collect_interface_data: true
  collect_peer_data: true
  collect_audit_data: true
  listening_address: ":8787"

mail:
  host: smtp.example.com
  port: 587
  encryption: starttls
  cert_validation: true
  username: wg-portal@example.com
  password: smtp_password_here
  from: "VPN Hub <wg-portal@example.com>"

auth:
  oidc: []
  oauth: []
  ldap: []
```

### Блок `core`

```yaml
core:
  admin_user: admin@example.com
  admin_password: ChangeMe_AtFirstLogin_12345
  editable_keys: true
  create_default_peer: false
  self_provisioning_allowed: false
  default_language: en
```

- **`admin_user` / `admin_password`** — учётка администратора, создаётся при первом запуске. **Обязательно смени пароль через UI** в первые же минуты после запуска. После этого можно оставить эти поля для аварийного входа или вычистить.
- **`editable_keys`** — разрешает редактировать ключи пиров через UI. Полезно, удобно при импорте существующих пиров.
- **`create_default_peer: false`** — выключает автосоздание пира при появлении нового пользователя (нужно, если ты используешь OIDC и не хочешь автогенерации).
- **`self_provisioning_allowed: false`** — обычные пользователи **не могут** сами себе создавать новые пиры через UI. Включай, только если ты доверяешь всем пользователям полностью.
- **`default_language`** — `en` или `ru` (если перевод есть). Можно сменить на пользователя позже в UI.

### Блок `advanced`

```yaml
advanced:
  config_storage_path: /app/data/wireguard
  expiry_check_interval: 15m
  rule_prio_offset: 20000
  route_table_offset: 20000
  api_admin_only: true
```

- **`config_storage_path`** — куда писать `wg0.conf` и т.п. Обычно дефолт устраивает.
- **`expiry_check_interval`** — как часто проверять истечение временных пиров (если используешь expire-функцию).
- **`rule_prio_offset` / `route_table_offset`** — числа, с которых начинаются ID правил/таблиц маршрутизации, создаваемых wg-portal. Меняй только если эти диапазоны заняты чем-то ещё на хосте.
- **`api_admin_only`** — `true` означает, что REST API доступен только админам. Очень рекомендую оставить.

### Блок `web`

```yaml
web:
  external_url: https://wg.lan.vpn
  listening_address: "127.0.0.1:8888"
  session_secret: REPLACE_WITH_LONG_RANDOM_STRING
  csrf_secret: ANOTHER_LONG_RANDOM_STRING
  site_title: "VPN Hub"
```

- **`external_url`** — внешний URL UI. Используется для генерации ссылок в письмах и QR-кодах. Должен совпадать с тем, что в DNS.
- **`listening_address: "127.0.0.1:8888"`** — слушаем ТОЛЬКО на loopback. Снаружи доступ — только через nginx с TLS (см. шаг 8). Это безопаснее, чем выставлять 8888 на всех интерфейсах.
- **`session_secret` / `csrf_secret`** — секреты для сессий и CSRF-токенов. Генерируй случайные:
  ```bash
  openssl rand -base64 48
  ```
  И в каждое поле — свой уникальный.

### Блок `database`

```yaml
database:
  type: sqlite
  dsn: /app/data/sqlite.db
```

Для нашего масштаба SQLite — оптимально: один файл, не нужен отдельный сервис, бэкап — `cp`. Если когда-нибудь упрётесь в производительность (а это случится только на тысячах пиров) — миграция на Postgres:

```yaml
database:
  type: postgres
  dsn: host=postgres user=wgportal password=secret dbname=wgportal sslmode=disable
```

И добавить сервис `postgres` в compose. До тех пор — не усложняй.

### Блок `statistics`

```yaml
statistics:
  use_ping_checks: true
  ping_check_workers: 10
  ping_unprivileged: false
  ping_check_interval: 1m
  data_collection_interval: 1m
  collect_interface_data: true
  collect_peer_data: true
  collect_audit_data: true
  listening_address: ":8787"
```

- **`use_ping_checks`** — wg-portal будет пинговать пиров, чтобы определить, действительно ли они онлайн (handshake может быть старый, а пир ушёл).
- **`listening_address: ":8787"`** — экспорт метрик в Prometheus-формате. Скрейпь его с мониторинг-сервера. Если мониторинга нет — закомментируй строку.
- **`collect_*`** — что собирать в БД. Хочешь видеть, кто и когда подключался — оставь всё `true`.

### Блок `mail`

Нужен, если хочешь отправлять конфиги клиентам по почте прямо из UI. Если не нужен — можно либо удалить блок целиком, либо оставить пустые поля.

### Блок `auth`

Для базовой установки пустые списки = только локальные пароли. Подробнее про OIDC/LDAP — в шаге 9.

---

## Шаг 4. Первый запуск

```bash
cd ~/wg-portal

# проверим, что compose валиден
docker compose config

# скачиваем образ
docker compose pull

# запускаем
docker compose up -d

# смотрим логи
docker compose logs -f wg-portal
```

В логах ищи:

```
INFO  starting WireGuard Portal v2.x.x
INFO  database migration completed
INFO  starting web server on 127.0.0.1:8888
INFO  starting statistics collector
```

Если есть ошибки — иди в [Типичные грабли](#типичные-грабли).

**Первый вход**: с самого хаба (поскольку UI на loopback):

```bash
curl -I http://127.0.0.1:8888/
# должен быть HTTP/1.1 200 OK или 302 Found на /login
```

Если ты ходишь на хаб по SSH с ноутбука — самый простой способ открыть UI — SSH-туннель:

```bash
ssh -L 8888:127.0.0.1:8888 hub.example.com
# в браузере на ноуте → http://localhost:8888
```

Залогинься как `admin@example.com` с паролем из `config.yaml`. **Сразу смени пароль** в `Settings → Account`.

---

## Шаг 5. Создание интерфейса wg0

В UI:

1. **Interfaces → Add a new interface** (рус: **Интерфейсы → Добавить новый интерфейс**).
2. Поля (англ. / рус.):
   - **Identifier** / *Идентификатор*: `wg0`
   - **Display Name** / *Отображаемое имя*: `Main VPN`
   - **Type / Mode** / *Тип / Режим*: `Server` (*Серверный*)
   - **Listen Port** / *Порт прослушивания*: `51820`
   - **IP addresses** / *IP-адреса*: `10.10.0.1/24`
   - **MTU**: `1420` (стандартный для WG поверх ethernet)
   - **Private Key** / *Приватный ключ*: нажми кнопку «Generate» — wg-portal создаст пару ключей. Публичный ключ сохрани — он пойдёт клиентам.
   - **Public Endpoint** / *Публичная конечная точка*: `hub.example.com:51820` — **это и есть тот самый Endpoint**, который попадёт в конфиги всех пиров автоматически. Поле уровня интерфейса, не уровня пира. Можно ставить домен (рекомендую) или публичный IP.
   - **DNS**: `10.10.0.1` (это поле для **пиров**, не для самого хаба. Пиры получат этот DNS в свой `wg0.conf`)
3. **Peer Defaults** / *Настройки пиров по умолчанию* — значения, которые будут проставляться у новых пиров при создании. У самих пиров **нет** отдельного поля Endpoint — он подставляется из «Публичной конечной точки» интерфейса (см. выше).
   - **AllowedIPs** / *Разрешенные IP-адреса*: `10.10.0.0/24`
   - **DNS**: `10.10.0.1`
   - **PersistentKeepalive** / *Интервал поддержания активности*: `25`
4. **Hooks** (`PostUp` / `PostDown`):

   **PostUp**:
   ```bash
   iptables -A FORWARD -i %i -o %i -j ACCEPT
   iptables -A FORWARD -i %i -j ACCEPT
   iptables -A FORWARD -o %i -j ACCEPT
   iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   ```

   **PostDown**:
   ```bash
   iptables -D FORWARD -i %i -o %i -j ACCEPT
   iptables -D FORWARD -i %i -j ACCEPT
   iptables -D FORWARD -o %i -j ACCEPT
   iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
   ```

   `%i` — wg-portal подставит сюда имя интерфейса (`wg0`). `eth0` замени на реальное имя WAN-интерфейса хаба (`ip route get 1.1.1.1` покажет).

   Разбор правил:
   - `FORWARD -i %i -o %i` — разрешает трафик между пирами через хаб (тема [«Hub-and-spoke + связь клиентов между собой»](wg-interconnect.md#топология-1-hub-and-spoke--связь-клиентов-между-собой)).
   - `FORWARD -i %i` / `FORWARD -o %i` — трафик из/в VPN в любую сторону.
   - `MASQUERADE -o eth0` — клиенты могут ходить в интернет через хаб (если поставить им `AllowedIPs = 0.0.0.0/0`). Если не хочешь, чтобы хаб был интернет-гейтом — убери эту строку.

5. **Save & Enable**.

Проверь на хосте:

```bash
sudo wg show
# wg0 должен появиться, без peer'ов пока

ip addr show wg0
# inet 10.10.0.1/24 scope global wg0

sudo iptables -L FORWARD -v -n | head
# счётчики на правилах должны быть, FORWARD политика — DROP с твоими ACCEPT правилами
```

---

## Шаг 6. Добавление обычного клиента (hub-and-spoke)

Сценарий: добавляем пользователя с ноутбука, которому нужен доступ к сервисам в VPN (`acme.lan.vpn`, `app.lan.vpn` и т.п.). Site-to-site не нужен.

1. **Peers → Add Peer**.
2. Поля:
   - **Interface**: `wg0`
   - **Display Name**: `Alice — Laptop`
   - **Identifier**: `alice-laptop` (произвольный)
   - **Linked User** (если используешь user accounts): `alice@example.com`
   - **IP addresses**: `10.10.0.2/32` (или нажми «Auto-assign» — выберет свободный из пула)
   - **AllowedIPs (на стороне клиента, что подставится в его конфиг)**: `10.10.0.0/24`
     Это говорит клиенту: «весь трафик к VPN-подсети шли через туннель». Если хочешь, чтобы у клиента **весь** интернет шёл через хаб — поставь `0.0.0.0/0` (и убедись, что на хабе есть MASQUERADE).
   - **Extra AllowedIPs (на стороне сервера, какие IP принимать от этого пира)**: оставь пустым.
     По умолчанию хаб примет только `10.10.0.2/32` от этого пира — что и нужно для обычного клиента.
   - **PersistentKeepalive** / *Интервал поддержания активности*: `25`
   - **DNS**: `10.10.0.1` (push-DNS на клиента)
   - **PresharedKey** / *Предварительный общий ключ*: «Generate». PSK — обязательный для прода (см. [vpn-setup.md#безопасность](vpn-setup.md)).

   > **Endpoint в форме пира НЕ ищи** — его там нет. Адрес, к которому будет коннектиться этот пир, берётся из поля «Публичная конечная точка» интерфейса `wg0` (см. шаг 5). При скачивании конфига wg-portal сам подставит туда `hub.example.com:51820`.
3. **Save**.

Теперь у пира появится страница с **QR-кодом** и кнопкой **Download Config**. Отправь Alice её конфиг (через safe-канал — Signal, например). На своей машине она:

```bash
sudo mv alice-laptop.conf /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
sudo wg-quick up wg0
sudo wg show
```

Через секунду в UI wg-portal у пира Alice появится свежий `latest handshake` и поедут байты.

---

## Шаг 7. Добавление site-to-site клиента

Сценарий: добавляем офис, где за роутером с WG стоит локальная сеть `192.168.20.0/24`. Хотим, чтобы из VPN был доступ к принтерам/NAS/PC в этой локалке.

Это место, где wg-portal сильно выигрывает у wg-easy: **в UI есть отдельное поле `Extra AllowedIPs`**, которое сохраняется и не теряется при следующем редактировании.

### 7.1. Создание пира в wg-portal

1. **Peers → Add Peer**.
2. Поля:
   - **Display Name**: `Office Moscow — Gateway`
   - **IP addresses**: `10.10.0.3/32`
   - **Extra AllowedIPs (на стороне сервера)**: **`192.168.20.0/24`**
     Это ключевое поле. wg-portal пропишет в конфиг хаба: `AllowedIPs = 10.10.0.3/32, 192.168.20.0/24` — то есть «принимай от этого пира пакеты с 10.10.0.3 ИЛИ с любого 192.168.20.x».
   - **AllowedIPs (на стороне клиента)**: `10.10.0.0/24`
     Это то, что попадёт в конфиг офисного роутера: «трафик к VPN-подсети — в туннель».
   - **PersistentKeepalive**: `25`
   - **PresharedKey**: «Generate».
3. **Save**.

### 7.2. На офисном роутере

Скачай конфиг из UI, положи на роутер. Дополнительно к стандартному `wg0.conf` нужно настроить форвардинг и MASQUERADE, потому что роутер должен работать как gateway для своей локалки:

`/etc/wireguard/wg0.conf` на офисном роутере:

```ini
[Interface]
Address    = 10.10.0.3/32
PrivateKey = <выданный wg-portal>
DNS        = 10.10.0.1

# ВАЖНО: эти PostUp/PostDown ДОЛЖНЫ быть на офисном роутере
PostUp   = sysctl -w net.ipv4.ip_forward=1
PostUp   = iptables -A FORWARD -i %i -o eth0 -j ACCEPT
PostUp   = iptables -A FORWARD -i eth0 -o %i -j ACCEPT
PostUp   = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o eth0 -j ACCEPT
PostDown = iptables -D FORWARD -i eth0 -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey    = <публичный ключ хаба>
PresharedKey = <PSK>
Endpoint     = hub.example.com:51820
AllowedIPs   = 10.10.0.0/24
PersistentKeepalive = 25
```

Поднимаешь:
```bash
sudo wg-quick up wg0
```

### 7.3. На клиенте, который хочет видеть офисную сеть

Теперь Alice (из шага 6) хочет ходить в `192.168.20.10` (NAS в офисе). Её текущий конфиг знает только про `10.10.0.0/24`. Нужно расширить.

В wg-portal: **Peers → Alice → Edit → AllowedIPs**:
```
10.10.0.0/24, 192.168.20.0/24
```
**Save**. wg-portal перегенерирует её конфиг. Скачать обновлённый и применить (`wg-quick down wg0 && wg-quick up wg0`).

Альтернатива: на самой машине Alice временно поправить `/etc/wireguard/wg0.conf` — добавить `, 192.168.20.0/24` в `AllowedIPs` пира хаба, и `wg-quick down/up`.

### 7.4. Проверка

С машины Alice:
```bash
ping 192.168.20.10
traceroute 192.168.20.10
# должен пройти через 10.10.0.1 (хаб), потом 10.10.0.3 (офисный роутер), потом цель
```

Подробнее про site-to-site и обратные маршруты — [wg-interconnect.md, топология 2](wg-interconnect.md#топология-2-site-to-site-объединение-целых-локалок).

---

## Шаг 8. HTTPS для UI через хостовой nginx

UI должен быть доступен админам по `https://wg.lan.vpn`. План:

1. Получить TLS-сертификат на `wg.lan.vpn` от внутреннего CA (через [acme-сервер](usage.md)).
2. Настроить nginx на хосте: проксирует 443 → `127.0.0.1:8888`.

### 8.1. Получаем сертификат

На хабе (или где запускаешь acme.sh / certbot):

```bash
acme.sh --issue -d wg.lan.vpn --standalone \
  --server https://acme.lan.vpn:8443/acme/acme/directory
acme.sh --install-cert -d wg.lan.vpn \
  --key-file       /etc/ssl/private/wg.lan.vpn.key \
  --fullchain-file /etc/ssl/certs/wg.lan.vpn.crt \
  --reloadcmd      "systemctl reload nginx"
```

### 8.2. nginx конфиг

`/etc/nginx/sites-available/wg-portal`:

```nginx
server {
    listen 80;
    server_name wg.lan.vpn;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name wg.lan.vpn;

    ssl_certificate     /etc/ssl/certs/wg.lan.vpn.crt;
    ssl_certificate_key /etc/ssl/private/wg.lan.vpn.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # ограничение по IP — UI доступен только из VPN-подсети
    # и из админской подсети в LAN
    allow 10.10.0.0/24;
    allow 192.168.1.0/24;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        # для websockets (live-обновление статистики в UI)
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        # таймауты побольше для скачивания QR-кодов и конфигов
        proxy_read_timeout 300s;
    }
}
```

Включить:
```bash
sudo ln -s /etc/nginx/sites-available/wg-portal /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 8.3. DNS-запись

На внутреннем DNS-сервере добавь:
```
wg.lan.vpn.   A   10.10.0.1
```
(или адрес хаба в LAN, если админы ходят из LAN, а не из VPN — зависит от того, где ты).

### 8.4. Проверка

С админской машины из VPN:
```bash
curl -v https://wg.lan.vpn/
# 200 OK, сертификат валидный (если корень CA добавлен в trust store)
```

---

## Шаг 9. Аутентификация через OIDC/LDAP

Опционально. Если у тебя есть LDAP (Active Directory, FreeIPA) или OIDC-провайдер (Keycloak, Authelia, Authentik) — можно подключить.

### Пример OIDC (Keycloak)

В `config.yaml`:

```yaml
auth:
  oidc:
    - id: keycloak
      provider_name: "Keycloak"
      display_name: "Sign in with Keycloak"
      base_url: https://keycloak.lan.vpn/realms/main
      client_id: wg-portal
      client_secret: <secret from Keycloak>
      extra_scopes: [profile, email]
      field_map:
        user_identifier: sub
        email: email
        firstname: given_name
        lastname: family_name
        is_admin: groups
      admin_mapping:
        admin_value_regex: ".*vpn-admins.*"
      registration_enabled: true
      log_user_info: false
```

После `docker compose restart wg-portal` на странице логина появится кнопка «Sign in with Keycloak».

Полный список поддерживаемых провайдеров и полей — в [официальной документации wg-portal](https://github.com/h44z/wg-portal/wiki).

### Пример LDAP

```yaml
auth:
  ldap:
    - id: company-ad
      provider_name: "Company AD"
      url: ldaps://ad.lan.vpn:636
      bind_user: "CN=wg-portal,OU=ServiceAccounts,DC=company,DC=local"
      bind_pass: secret
      base_dn: "DC=company,DC=local"
      login_filter: "(&(objectClass=user)(sAMAccountName={{login}}))"
      admin_group: "CN=VPN-Admins,OU=Groups,DC=company,DC=local"
      sync_filter: "(objectClass=user)"
      sync_interval: 30m
      field_map:
        user_identifier: sAMAccountName
        email: mail
        firstname: givenName
        lastname: sn
      registration_enabled: true
```

---

## Шаг 10. REST API и автоматизация

wg-portal даёт REST API на том же порту, что и UI (`/api/v0/...`). Аутентификация — через API-токены или сессию.

### Создание API-токена

В UI: **Profile → API Tokens → Generate New Token**. Сохрани сразу — больше не покажет.

### Примеры запросов

```bash
TOKEN="<your-token>"
HUB="https://wg.lan.vpn"

# список всех пиров
curl -H "Authorization: Bearer $TOKEN" $HUB/api/v0/peer

# создать нового пира
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  $HUB/api/v0/peer \
  -d '{
    "InterfaceIdentifier": "wg0",
    "DisplayName": "auto-created-bob",
    "AddressStr": "10.10.0.42/32",
    "PersistentKeepalive": 25
  }'

# скачать конфиг пира
curl -H "Authorization: Bearer $TOKEN" \
  $HUB/api/v0/peer/<peer-id>/config > bob.conf
```

### Примеры автоматизации

- **Onboarding нового сотрудника**: HR-система → webhook → скрипт создаёт пира в wg-portal через API → отправляет конфиг сотруднику по почте.
- **Интеграция с ACME**: при создании пира — автоматически выпускать ему сертификат на внутренний домен.
- **Off-boarding**: при увольнении — скрипт удаляет пира.

Полная схема API доступна в самом UI: **? → API Docs** (Swagger).

---

## Бэкапы

Что критично сохранять:

1. **`data/sqlite.db`** — пиры, ключи, статистика, аудит.
2. **`data/wireguard/`** — сгенерированные конфиги интерфейсов.
3. **`config/config.yaml`** — конфиг wg-portal с секретами.

### Простой ежедневный бэкап

`/etc/cron.daily/wg-portal-backup`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR=/var/backups/wg-portal
DATE=$(date +%F)
mkdir -p "$BACKUP_DIR"

# горячий бэкап SQLite через .backup команду — атомарный
docker compose -f /home/admin/wg-portal/docker-compose.yml \
  exec -T wg-portal sqlite3 /app/data/sqlite.db ".backup /app/data/backup.db"

tar czf "$BACKUP_DIR/wg-portal-$DATE.tgz" \
  -C /home/admin/wg-portal \
  config/ \
  data/

# опционально — выгрузка на удалённое хранилище
# rsync -a "$BACKUP_DIR/wg-portal-$DATE.tgz" backup-server:/backups/

# чистка старых
find "$BACKUP_DIR" -name "wg-portal-*.tgz" -mtime +30 -delete
```

```bash
sudo chmod +x /etc/cron.daily/wg-portal-backup
sudo /etc/cron.daily/wg-portal-backup    # проверка
```

### Восстановление

```bash
docker compose down
tar xzf /var/backups/wg-portal/wg-portal-YYYY-MM-DD.tgz -C /home/admin/wg-portal/
docker compose up -d
```

**Внимание**: если при восстановлении меняются ключи интерфейса хаба (`PrivateKey` для `wg0`) — клиентам не придётся перевыпускать конфиги (у них `PublicKey` хаба, он не меняется при восстановлении из бэкапа). А вот если потеряешь БД и переустановишь wg-portal с нуля — ключи сгенерятся новые, всем клиентам новые конфиги. Делай бэкап.

---

## Обновление wg-portal

```bash
cd ~/wg-portal

# смотрим что доступно
docker compose pull

# обновляем
docker compose up -d

# проверяем логи на ошибки миграции БД
docker compose logs --tail 100 wg-portal
```

**Правила**:
- Перед обновлением — бэкап. Всегда.
- Не обновляй между мажорными версиями (v2 → v3) без чтения CHANGELOG: могут быть несовместимые изменения формата конфига.
- Если что-то сломалось — откат через бэкап:
  ```bash
  docker compose down
  tar xzf /var/backups/wg-portal/wg-portal-YYYY-MM-DD.tgz -C ./
  # в docker-compose.yml зафиксируй старый тег
  docker compose up -d
  ```

---

## Мониторинг

### Prometheus метрики

wg-portal экспортирует метрики на `:8787/metrics` (если включён блок `statistics.listening_address`).

В Prometheus:

```yaml
scrape_configs:
  - job_name: wg-portal
    static_configs:
      - targets: ['10.10.0.1:8787']
```

Что мониторить:
- `wgportal_peer_handshake_seconds` — давность handshake. Алерт, если > 300 секунд при `PersistentKeepalive=25`.
- `wgportal_peer_bytes_received_total` / `_sent_total` — счётчики трафика.
- `wgportal_interface_peers` — число пиров на интерфейсе.

### Базовые алерты

```yaml
groups:
  - name: wg-portal
    rules:
      - alert: WGPeerHandshakeStale
        expr: time() - wgportal_peer_handshake_seconds > 600
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Peer {{ $labels.peer }} не делал handshake > 10 минут"

      - alert: WGPortalDown
        expr: up{job="wg-portal"} == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "wg-portal недоступен"
```

### Логи

```bash
# поток логов
docker compose logs -f wg-portal

# собирать в journald (по умолчанию у docker)
journalctl -u docker -f | grep wg-portal
```

Для центрального лога — пробрось в Loki/ELK через docker logging driver.

---

## Типичные грабли

### `cannot create wireguard interface: operation not permitted`

Не хватает `cap_add: NET_ADMIN` или контейнер не в `network_mode: host`.

### `address already in use` для 51820

На хосте уже запущен `wg-quick@wg0` или другой процесс на UDP 51820. Останови:
```bash
sudo systemctl stop wg-quick@wg0
sudo systemctl disable wg-quick@wg0
sudo ss -ulnp | grep 51820
```

### UI работает, но клиенты не подключаются

Проверь по порядку:
1. UDP 51820 открыт во внешнем фаерволе? `sudo nft list ruleset` / `sudo iptables -L -n -v`.
2. На хосте ip_forward = 1? `sysctl net.ipv4.ip_forward`.
3. Интерфейс реально поднят? `sudo wg show wg0`.
4. PostUp правила применились? `sudo iptables -L FORWARD -v -n`.
5. У пира клиента в `Endpoint` скачанного `wg0.conf` правильный публичный адрес хаба, а не внутренний? Если нет — поправь поле **«Публичная конечная точка»** в настройках интерфейса `wg0` на хабе и перевыпусти конфиги пиров.

### `iptables: command not found` в логах

Образ wg-portal обычно содержит iptables, но если ты используешь альтернативный образ — проверь. В крайнем случае монтируй с хоста: `volumes: - /usr/sbin/iptables:/usr/sbin/iptables:ro`.

### Изменения в `Extra AllowedIPs` не применяются

Сохрани пира и **перезапусти интерфейс** через UI (`Interfaces → wg0 → Restart`). wg-portal обычно делает это автоматически, но иногда требуется ручной триггер.

### nginx 502 Bad Gateway при заходе на `https://wg.lan.vpn`

Скорее всего wg-portal не слушает на 8888 или слушает не на 127.0.0.1, а на чём-то другом. Проверь:
```bash
sudo ss -tlnp | grep 8888
curl -I http://127.0.0.1:8888/
```

### Конфиг клиента работает, но `ping` до хаба не идёт

Возможно ты случайно пропустил пира в **Extra AllowedIPs** (поле «что хаб принимает от этого пира»). Хаб дропает входящие пакеты, если их source IP не входит в этот список.

### Сертификат в `acme.json` Traefik (на клиенте) пропал после обновления wg-portal

Это, скорее всего, совпадение — wg-portal не трогает чужие тома. Но проверь, что в `/app/data/wireguard/` тоже всё на месте.

---

## Чек-лист перед уходом в прод

- [ ] Дефолтный пароль `admin_password` сменён через UI, в `config.yaml` стоит **сложный** временный.
- [ ] `session_secret` и `csrf_secret` — сгенерированы случайно, длина ≥ 32 символа.
- [ ] UI слушает только на `127.0.0.1:8888`, наружу — через nginx с TLS.
- [ ] TLS-сертификат на `wg.lan.vpn` валиден (внутренний CA, см. [usage.md](usage.md)).
- [ ] В nginx настроен IP-allowlist (`allow ...; deny all;`) — UI доступен только из доверенных подсетей.
- [ ] UDP 51820 открыт во внешнем фаерволе.
- [ ] `net.ipv4.ip_forward=1` сохранится после ребута (`/etc/sysctl.d/99-wg.conf`).
- [ ] Создан хотя бы один тестовый пир, проверена связность через VPN.
- [ ] Создан хотя бы один site-to-site пир (если планируется), проверен `ping` в локалку.
- [ ] Бэкап-скрипт лежит в `/etc/cron.daily/`, протестирован запуск.
- [ ] Образ зафиксирован на конкретной версии (`:v2.x.y`), не `latest`.
- [ ] Prometheus скрейпит `:8787/metrics`, алерты настроены.
- [ ] PSK включён для всех пиров (`PresharedKey` в каждом).
- [ ] План восстановления при потере БД задокументирован (что делать, если sqlite.db умер).
- [ ] Доступ в UI ограничен только админам, обычные пользователи не могут самовольно создавать пиров (`self_provisioning_allowed: false`).

---

## Связанные документы

- [vpn-setup.md](vpn-setup.md) — общая схема VPN, внутренний DNS, изначальная настройка хаба.
- [wg-interconnect.md](wg-interconnect.md) — топологии, объединение сетей, site-to-site в деталях.
- [wg-traefik-client-setup.md](wg-traefik-client-setup.md) — клиентская сторона: WG-клиент + Traefik за ACME.
- [usage.md](usage.md) — как пользоваться самим ACME-сервером для выпуска внутренних сертификатов.
