# DNS + ACME на отдельном пире VPN

Подробный сквозной гайд: как поднять отдельную сервисную машину с **WireGuard-клиентом**, **CoreDNS** и **ACME-сервером (secutor-acme)** в одном `docker-compose.yml`. Машина подключается к хабу (см. [wg-portal-hub.md](wg-portal-hub.md)) как обычный пир с фиксированным IP, а внутри неё все три сервиса шарят сетевой namespace WG-клиента и слушают только на VPN-адресе.

Этот документ — альтернатива схеме из [vpn-setup.md](vpn-setup.md), где DNS и ACME живут на самом хабе. Если хочется разделить ответственности, иметь возможность перезагрузить DNS/ACME независимо от хаба, или у тебя просто нет рута на хабе — это твой вариант.

## Содержание

- [Зачем это нужно](#зачем-это-нужно)
- [Сравнение со схемой «всё на хабе»](#сравнение-со-схемой-всё-на-хабе)
- [Цель и предусловия](#цель-и-предусловия)
- [Что в итоге получится](#что-в-итоге-получится)
- [Архитектура](#архитектура)
- [Шаг 1. Регистрация пира в wg-portal](#шаг-1-регистрация-пира-в-wg-portal)
- [Шаг 2. Подготовка сервисной машины](#шаг-2-подготовка-сервисной-машины)
- [Шаг 3. Структура каталога](#шаг-3-структура-каталога)
- [Шаг 4. wg/wg0.conf](#шаг-4-wgwg0conf)
- [Шаг 5. CoreDNS: Corefile и зона](#шаг-5-coredns-corefile-и-зона)
- [Шаг 6. ACME-сервер (secutor-acme)](#шаг-6-acme-сервер-secutor-acme)
- [Шаг 7. docker-compose.yml](#шаг-7-docker-composeyml)
- [Шаг 8. Первый запуск](#шаг-8-первый-запуск)
- [Шаг 9. Проверка end-to-end](#шаг-9-проверка-end-to-end)
- [Шаг 10. Переключение клиентов на новый DNS](#шаг-10-переключение-клиентов-на-новый-dns)
- [Шаг 11. Регистрация trust anchor у клиентов](#шаг-11-регистрация-trust-anchor-у-клиентов)
- [Бэкапы](#бэкапы)
- [Обновление сервисов](#обновление-сервисов)
- [Альтернатива: BIND с TSIG для DNS-01 challenge](#альтернатива-bind-с-tsig-для-dns-01-challenge)
- [Мониторинг](#мониторинг)
- [Типичные грабли](#типичные-грабли)
- [Чек-лист перед уходом в прод](#чек-лист-перед-уходом-в-прод)
- [Связанные документы](#связанные-документы)

---

## Зачем это нужно

В [vpn-setup.md](vpn-setup.md) описана схема, где хаб одновременно:
- терминирует WireGuard-соединения,
- держит ACME-сервер,
- держит внутренний DNS.

Это работает, но смешивает три разные роли на одной машине. Альтернатива — вынести **DNS + ACME** на отдельный пир. Тогда хаб занимается только VPN, а сервисы — отдельная сущность, которую можно:
- держать на другой физической машине (или даже в другом ДЦ),
- обслуживать своим админом,
- обновлять/перезагружать независимо от хаба.

Цена — лишний сетевой хоп для каждого DNS-запроса (клиент → хаб → сервисный пир). На практике это микросекунды, незаметно.

---

## Сравнение со схемой «всё на хабе»

| Аспект | Всё на хабе | DNS + ACME на пире |
|---|---|---|
| Сложность установки | Проще: один compose | Два compose (хаб + пир), но каждый меньше |
| Ответственность | Один админ держит всё | Можно разделить между админами |
| Перезагрузка DNS/ACME | Влияет на работу WG | Не влияет |
| Перезагрузка хаба | Влияет на всё | Влияет на всё (без VPN до DNS не дотянуться) |
| Сетевая нагрузка | Минимальная | +1 хоп для DNS-запросов |
| Аутентификация в CoreDNS зоне | Локальный сокет | Через VPN, по IP |
| Удобство при разных физических площадках | Хуже | Лучше: DNS можно поставить ближе к клиентам |

**Когда выбрать «на пире»**:
- Хаб — VPS у провайдера, рут — у провайдера, а ACME-сервер с приватными ключами CA ставить на чужом хосте не хочется.
- Уже есть железо для сервисов, и оно не совпадает с тем, где WG-сервер.
- Хочется чистого разделения ролей.

**Когда выбрать «всё на хабе»**:
- Это твоя собственная одна машина.
- Сервисов мало, инфраструктура простая.
- Не хочется тянуть второй compose.

---

## Цель и предусловия

**Цель**: на сервисной машине поднять три контейнера:
- `wg` — WG-клиент, подключается к хабу как пир `10.10.0.53`.
- `coredns` — слушает `10.10.0.53:53`, отдаёт зону `lan.vpn`.
- `acme` — наш [secutor-acme](README.md), слушает `10.10.0.53:8443`.

Всё через VPN, никакие порты не торчат наружу.

**Что должно быть готово**:

1. **Хаб с wg-portal** уже работает по [wg-portal-hub.md](wg-portal-hub.md), интерфейс `wg0` поднят, подсеть `10.10.0.0/24`.
2. **Сервисная машина**: Linux, Docker, docker-compose v2. Это может быть VPS у любого провайдера, домашний сервер, NAS с Docker — что угодно. Публичный IP **не нужен** — мы клиент, инициатор соединения.
3. **CA уже создана и подготовлена** по [ca-lifecycle.md](ca-lifecycle.md): root оффлайн в бэкапах, intermediate готов к доставке на сервисную машину. Этот документ предполагает, что ты идёшь с **intermediate context**, а не с root'ом. Если CA ещё нет — иди сначала туда.
4. **Доступ к web-UI wg-portal** для регистрации нового пира.

---

## Что в итоге получится

После всех шагов:

- Сервисная машина держит постоянное WG-соединение с хабом. IP в VPN — `10.10.0.53`.
- CoreDNS отдаёт зону `lan.vpn` всем пирам VPN, резолвит `*.lan.vpn` в адреса из `10.10.0.0/24`, остальное — форвардит на внешние резолверы.
- ACME-сервер слушает на `https://acme.lan.vpn:8443/acme/acme/directory`, доступен из всей VPN.
- Все клиенты VPN получают `DNS = 10.10.0.53` через push из wg-portal.
- Корневой сертификат CA доступен скачиванием по `http://acme.lan.vpn/root.crt` (опционально).

---

## Архитектура

```
                       Интернет
                          │
                          │ UDP 51820
                          ▼
       ┌──────────────────────────────────┐
       │  Hub (wg-portal, 10.10.0.1)       │
       │  - WireGuard сервер               │
       │  - маршрутизация между пирами     │
       └────────────┬─────────────────────┘
                    │ wg0  10.10.0.0/24
        ┌───────────┼────────────────────────────┐
        │           │                             │
   ┌────▼────┐ ┌────▼─────┐               ┌──────▼──────┐
   │ peer A  │ │ peer B   │               │ peer        │
   │ 10.0.2  │ │ 10.0.3   │               │ "services"  │
   │ юзер    │ │ офис     │               │ 10.10.0.53  │
   └─────────┘ └──────────┘               │             │
                                           │  ┌────────┐│
                                           │  │ wg     ││
                                           │  │ wg0    ││
                                           │  └───┬────┘│
                                           │      │ shares ns
                                           │  ┌───▼────┐│
                                           │  │coredns ││
                                           │  │ :53    ││
                                           │  └────────┘│
                                           │  ┌────────┐│
                                           │  │ acme   ││
                                           │  │ :8443  ││
                                           │  └────────┘│
                                           └─────────────┘
```

**Ключевые решения** (те же, что в [wg-traefik-client-setup.md](wg-traefik-client-setup.md)):

- Один `wg`-контейнер устанавливает туннель и **единственный** имеет свой собственный network namespace.
- `coredns` и `acme` получают **тот же** namespace через `network_mode: "service:wg"`. Они видят `wg0` как родной интерфейс и слушают порты на `10.10.0.53`.
- Снаружи VPN сервисы недоступны — никакие `ports:` на хост не пробрасываются.
- ACME-сервер ходит за DNS на `127.0.0.1:53` (это CoreDNS в том же namespace).

---

## Шаг 1. Регистрация пира в wg-portal

Делается **на хабе**, через web-UI wg-portal по `https://wg.lan.vpn`.

1. **Peers → Add Peer**.
2. Поля:
   - **Interface**: `wg0`
   - **Display Name**: `Services — DNS + ACME`
   - **Identifier**: `services-dns-acme`
   - **IP addresses**: `10.10.0.53/32` (фиксируем адрес — на нём будут слушать сервисы)
   - **AllowedIPs (на стороне клиента)**: `10.10.0.0/24`
     Этот пир ходит только внутри VPN. Если хочешь, чтобы у него ещё и весь интернет шёл через хаб — поставь `0.0.0.0/0`, но обычно не нужно.
   - **Extra AllowedIPs (на стороне сервера)**: оставь **пустым** или поставь только `10.10.0.53/32`.
     Этот пир не представляет никакую подсеть, только сам себя.
   - **PersistentKeepalive**: `25`
   - **DNS (push на пира)**: **оставь пустым** или поставь `127.0.0.1`.
     ⚠️ Очень важный момент. Если поставишь сюда `10.10.0.53` — получишь курицу-яйцо: сервисная машина сама же является своим DNS-сервером, но при старте wg-quick попытается прописать DNS `10.10.0.53` ещё до того, как CoreDNS запустится. Лечится либо пустым полем, либо `127.0.0.1`.
   - **Endpoint**: `hub.example.com:51820` (публичный адрес хаба)
   - **PresharedKey**: «Generate».
3. **Save**.

Скачай сгенерированный конфиг — это будет `wg/wg0.conf` на сервисной машине.

---

## Шаг 2. Подготовка сервисной машины

На сервисной машине (можно по SSH):

### 2.1. Базовые проверки

```bash
docker compose version          # должен ответить
modprobe wireguard              # модуль доступен
lsmod | grep wireguard
```

### 2.2. Включить ip_forward

Технически на сервисном пире форвардинг не нужен (мы не маршрутизатор), но дешевле включить заранее — пригодится, если позже добавишь что-то ещё:

```bash
sudo tee /etc/sysctl.d/99-wg-client.conf <<EOF
net.ipv4.conf.all.src_valid_mark = 1
EOF
sudo sysctl -p /etc/sysctl.d/99-wg-client.conf
```

### 2.3. Открыть исходящий UDP

Обычно фаервол разрешает исходящие соединения по умолчанию. Если у тебя политика «default deny outbound» — добавь:

```bash
sudo ufw allow out to hub.example.com port 51820 proto udp
```

(`ufw` или эквивалент в твоём фаерволе.)

---

## Шаг 3. Структура каталога

```bash
mkdir -p ~/services/{wg,coredns/zones,acme/{config,data,secrets,context}}
cd ~/services
```

Финальная структура:

```
~/services/
├── docker-compose.yml
├── wg/
│   └── wg0.conf                         # из wg-portal
├── coredns/
│   ├── Corefile                         # конфиг CoreDNS
│   └── zones/
│       └── lan.vpn.zone                 # зона DNS
└── acme/
    ├── config/
    │   └── config.yaml                  # конфиг secutor-acme
    ├── data/                            # SQLite БД секутора (rw, создастся)
    ├── secrets/
    │   └── context_password.txt         # пароль CA-контекста (chmod 600)
    └── context/                         # bind-mount твоего CA-контекста (ro)
        ├── store.enc
        ├── meta.json
        └── ...
```

Установи права:

```bash
chmod 700 acme/secrets acme/data
chmod 600 acme/secrets/context_password.txt 2>/dev/null || true
```

CA-контекст скопируй с админской машины:

```bash
# на админской машине, ВАЖНО: только intermediate, не root!
# (root живёт оффлайн, см. ca-lifecycle.md)
rsync -av --chmod=600 \
  ~/.secutor/contexts/intermediate/ \
  services-host:~/services/acme/context/
```

---

## Шаг 4. wg/wg0.conf

Возьми тот, который скачал из wg-portal. Должен выглядеть примерно так:

```ini
[Interface]
PrivateKey = <выданный wg-portal>
Address    = 10.10.0.53/32
# DNS НЕ указываем — иначе wg-quick попытается прописать 10.10.0.53,
# а CoreDNS на нём ещё не запущен (курица-яйцо)

[Peer]
PublicKey    = <публичный ключ хаба>
PresharedKey = <PSK из wg-portal>
Endpoint     = hub.example.com:51820
AllowedIPs   = 10.10.0.0/24
PersistentKeepalive = 25
```

Положи в `wg/wg0.conf` и поставь права:

```bash
chmod 600 wg/wg0.conf
```

---

## Шаг 5. CoreDNS: Corefile и зона

### 5.1. Corefile

`coredns/Corefile`:

```caddy
# Авторитативная зона lan.vpn
lan.vpn:53 {
    file /etc/coredns/zones/lan.vpn.zone
    log
    errors
    reload 30s
}

# Прямой и обратный ресолв для VPN-подсети (PTR-записи опциональны)
0.10.10.in-addr.arpa:53 {
    file /etc/coredns/zones/lan.vpn.zone
    log
    errors
}

# Всё остальное — рекурсивно на внешние резолверы
.:53 {
    forward . 1.1.1.1 8.8.8.8 {
        max_concurrent 1000
    }
    cache 300
    log
    errors
    prometheus :9153
}
```

**Что делает каждая строка**:

- `lan.vpn:53 { ... }` — авторитативный блок для внутренней зоны. CoreDNS отдаёт записи из файла, не идёт никуда наружу.
- `file /etc/coredns/zones/lan.vpn.zone` — путь к BIND-формат zone-файлу.
- `reload 30s` — CoreDNS перечитывает файл каждые 30 секунд. Удобно при редактировании.
- `.:53 { ... }` — fallback для всего остального. `forward` шлёт запрос на внешние резолверы.
- `prometheus :9153` — экспортирует метрики CoreDNS для скрейпа.

CoreDNS внутри namespace `service:wg` автоматически слушает на всех адресах внутри namespace, включая `10.10.0.53`. Привязка `bind 10.10.0.53` не нужна (можно добавить, если хочется явно).

### 5.2. Zone-файл

`coredns/zones/lan.vpn.zone`:

```dns
$ORIGIN lan.vpn.
$TTL 300

@           IN  SOA   ns.lan.vpn. admin.lan.vpn. (
                      2024112701  ; serial
                      3600        ; refresh
                      900         ; retry
                      604800      ; expire
                      300 )       ; minimum

@           IN  NS    ns.lan.vpn.

; === инфраструктура ===
ns          IN  A     10.10.0.53
hub         IN  A     10.10.0.1
wg          IN  A     10.10.0.1
acme        IN  A     10.10.0.53

; === пользовательские пиры ===
alice       IN  A     10.10.0.2
office-msk  IN  A     10.10.0.3
db          IN  A     10.10.0.4
app         IN  A     10.10.0.10
```

**Правила**:

- **Serial обязательно увеличивай** при каждой правке (формат `YYYYMMDDNN`). Без этого вторичные DNS-сервера (если появятся) не подхватят обновление.
- `$TTL 300` — пять минут. Достаточно низко, чтобы изменения распространялись быстро, достаточно высоко, чтобы не нагружать CoreDNS.
- `acme.lan.vpn → 10.10.0.53` — ACME-сервер на этой же машине.
- `wg.lan.vpn → 10.10.0.1` — wg-portal на хабе.
- Добавляй пользовательские A-записи по мере появления пиров.

### 5.3. Автоматизация зоны (опционально)

Если устал руками держать зону в синхронизации с wg-portal — у wg-portal есть REST API и webhook-хуки. Можно написать маленький скрипт, который при создании пира в wg-portal автоматически добавляет A-запись в zone-файл и увеличивает serial. Образец — в [wg-portal-hub.md, шаг 10](wg-portal-hub.md#шаг-10-rest-api-и-автоматизация).

---

## Шаг 6. ACME-сервер (secutor-acme)

### 6.1. config/config.yaml

`acme/config/config.yaml` (минимальный пример, см. полную референс-схему в [deployment.md](deployment.md)):

```yaml
# Прослушивание
listen:
  acme: "0.0.0.0:8443"        # ACME API, доступен на 10.10.0.53 через wg namespace
  metrics: "0.0.0.0:9100"     # Prometheus

# Публичный URL, попадает в /directory
base_url: "https://acme.lan.vpn:8443/"

# Резолверы — ходим через CoreDNS в том же namespace
resolvers:
  - "127.0.0.1:53"

# Политика выпуска
issuance:
  default_validity: 90d
  allowed_domains:
    - "*.lan.vpn"
  challenge_types:
    - tls-alpn-01
    - http-01
    # - dns-01    # требует TSIG-обновлений, см. альтернативу с BIND ниже

# Логи
logging:
  level: info
  format: json
```

### 6.2. Пароль контекста

`acme/secrets/context_password.txt` — пароль **intermediate** context'а (не root'а! root живёт оффлайн и его пароль на сервисной машине не должен появляться никогда). Подробно про разделение root/intermediate и почему здесь именно intermediate — в [ca-lifecycle.md](ca-lifecycle.md).

**Один пароль = одна строка без перевода**:

```bash
# ВАРИАНТ 1: интерактивно (рекомендую — не попадёт в bash history)
read -s -p "Intermediate password: " PWD
echo -n "$PWD" > acme/secrets/context_password.txt
unset PWD
chmod 600 acme/secrets/context_password.txt

# ВАРИАНТ 2: одной командой (пароль засветится в history!)
echo -n "your-intermediate-password-here" > acme/secrets/context_password.txt
chmod 600 acme/secrets/context_password.txt

# проверка, что в конце нет \n
xxd acme/secrets/context_password.txt | tail -1   # последний байт ≠ 0a
```

### 6.3. CA-контекст

Лежит в `acme/context/` — это **read-only** копия `~/.secutor/contexts/prod/`. Содержит:
- `store.enc` — зашифрованный приватный ключ CA,
- `cert.pem` — публичный сертификат CA,
- `meta.json` — метаданные.

Скопировал на шаге 3.

---

## Шаг 7. docker-compose.yml

`docker-compose.yml`:

```yaml
services:
  # === WireGuard клиент: единственный с собственным network namespace ===
  wg:
    image: linuxserver/wireguard:latest
    container_name: wg
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      net.ipv4.conf.all.src_valid_mark: 1
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Moscow
    volumes:
      - ./wg/wg0.conf:/config/wg_confs/wg0.conf:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wg", "show", "wg0"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 15s

  # === CoreDNS: разделяет namespace wg, слушает на 10.10.0.53:53 ===
  coredns:
    image: coredns/coredns:1.11.3
    container_name: coredns
    network_mode: "service:wg"
    depends_on:
      wg:
        condition: service_healthy
    command: ["-conf", "/etc/coredns/Corefile"]
    volumes:
      - ./coredns/Corefile:/etc/coredns/Corefile:ro
      - ./coredns/zones:/etc/coredns/zones:ro
    restart: unless-stopped

  # === ACME-сервер (secutor-acme): разделяет namespace wg, слушает 10.10.0.53:8443 ===
  acme:
    image: secutor-acme:1.0.0
    container_name: acme
    network_mode: "service:wg"
    depends_on:
      wg:
        condition: service_healthy
      coredns:
        condition: service_started
    read_only: true
    environment:
      SECUTOR_CONTEXT_DIR: /secutor/context
      SECUTOR_CONTEXT_PASSWORD_FILE: /run/secrets/context_password
      SECUTOR_ACME_DB: /var/lib/secutor-acme/acme.db
      SECUTOR_ACME_CONFIG: /etc/secutor-acme/config.yaml
      SECUTOR_ACME_LISTEN: "0.0.0.0:8443"
      SECUTOR_ACME_BASE_URL: "https://acme.lan.vpn:8443/"
    volumes:
      - type: bind
        source: ./acme/context
        target: /secutor/context
        read_only: true
      - secutor-acme-data:/var/lib/secutor-acme
      - ./acme/config/config.yaml:/etc/secutor-acme/config.yaml:ro
    secrets:
      - context_password
    restart: unless-stopped

secrets:
  context_password:
    file: ./acme/secrets/context_password.txt

volumes:
  secutor-acme-data:
```

### Разбор по сервисам

**`wg`** — без изменений по сравнению с [wg-traefik-client-setup.md](wg-traefik-client-setup.md). Главное:
- `cap_add: NET_ADMIN, SYS_MODULE` — для создания интерфейса.
- `wg0.conf` read-only из bind-mount.
- `healthcheck` — нужен, чтобы остальные сервисы стартовали только после установления туннеля.

**`coredns`**:
- `network_mode: "service:wg"` — садится в namespace wg, не имеет собственной сети. **Никакие `networks:` или `ports:` для него указывать нельзя** — будет ошибка docker-compose.
- `depends_on: wg condition: service_healthy` — стартует только после успешного handshake.
- Версия образа зафиксирована (`1.11.3`), не `latest`.

**`acme`**:
- Тоже `network_mode: "service:wg"`. ACME слушает на `0.0.0.0:8443` **внутри namespace**, что эквивалентно `10.10.0.53:8443` снаружи.
- `read_only: true` — корневая ФС read-only, всё запись идёт в volume `secutor-acme-data`.
- `depends_on: coredns` — ACME при старте делает резолв своего же `base_url` для валидации; нужно, чтобы CoreDNS уже отвечал.
- CA-контекст подмонтирован read-only — секутор не должен иметь возможности туда писать.
- Пароль через docker secret, не env. См. [deployment.md, раздел Docker secrets](deployment.md).

---

## Шаг 8. Первый запуск

```bash
cd ~/services

# проверим, что compose валиден
docker compose config

# скачаем образы
docker compose pull

# стартуем
docker compose up -d

# смотрим, как поднимается
docker compose ps
docker compose logs -f
```

Порядок ожидаемых событий:

1. `wg` стартует, поднимает интерфейс, делает handshake → healthcheck зелёный.
2. `coredns` стартует, привязывается к 53 внутри namespace, отвечает на запросы.
3. `acme` стартует, разблокирует CA через пароль, поднимает HTTPS на 8443, отвечает на `/directory`.

В логах ищи:

```
wg       | [#] wg-quick up wg0
wg       | [#] handshake (initial) ... succeeded
coredns  | CoreDNS-1.11.3
coredns  | linux/amd64, go1.21, ...
coredns  | Reloading complete
acme     | {"level":"info","msg":"context unlocked","name":"prod"}
acme     | {"level":"info","msg":"ACME directory served","url":"https://acme.lan.vpn:8443/directory"}
```

Если в логах есть ошибки — [Типичные грабли](#типичные-грабли).

---

## Шаг 9. Проверка end-to-end

### 9.1. Туннель установлен

```bash
docker compose exec wg wg show
# должен быть свежий handshake, transfer растёт
```

### 9.2. CoreDNS отвечает изнутри namespace

```bash
docker compose exec wg nslookup acme.lan.vpn 127.0.0.1
# Server: 127.0.0.1
# Address: 127.0.0.1#53
# Name: acme.lan.vpn
# Address: 10.10.0.53
```

### 9.3. CoreDNS отвечает с хаба

С хаба (или с любого другого пира VPN, который уже подключён):

```bash
dig @10.10.0.53 acme.lan.vpn +short
# 10.10.0.53

dig @10.10.0.53 wg.lan.vpn +short
# 10.10.0.1

dig @10.10.0.53 google.com +short
# должен вернуться внешний IP — форвардер работает
```

Если запрос с хаба не доходит — проверь, что на хабе в `iptables` есть правило, разрешающее форвардинг между пирами (в [wg-portal-hub.md, шаг 5](wg-portal-hub.md#шаг-5-создание-интерфейса-wg0) это PostUp `FORWARD -i %i -o %i -j ACCEPT`).

### 9.4. ACME отвечает

```bash
# с самой сервисной машины
docker compose exec wg curl -sk https://127.0.0.1:8443/directory | jq

# с хаба
curl -sk https://acme.lan.vpn:8443/directory | jq
```

Должен прийти JSON с `newAccount`, `newOrder`, `newNonce` и т.п.

### 9.5. Метрики CoreDNS и ACME

```bash
docker compose exec wg curl -s http://127.0.0.1:9153/metrics | head
docker compose exec wg curl -s http://127.0.0.1:9100/metrics | head
```

---

## Шаг 10. Переключение клиентов на новый DNS

Сейчас клиенты VPN получают `DNS = 10.10.0.1` (хаб). Надо перевести на `10.10.0.53`.

### 10.1. Через wg-portal (все новые пиры)

В UI:

1. **Interfaces → wg0 → Edit → Peer Defaults**:
   - **DNS**: смени с `10.10.0.1` на `10.10.0.53`.
   - Сохрани.

Теперь у всех **новых** пиров сразу будет правильный DNS.

### 10.2. Существующие пиры

Для каждого активного пира:

1. **Peers → выбираешь пира → Edit**.
2. Поле **DNS**: `10.10.0.53`.
3. Сохрани, скачай новый конфиг.
4. Отправь клиенту, он применяет:
   ```bash
   sudo wg-quick down wg0
   sudo mv ~/Downloads/<peer>.conf /etc/wireguard/wg0.conf
   sudo wg-quick up wg0
   ```

### 10.3. Сам сервисный пир

⚠️ **Не меняй DNS у сервисного пира на `10.10.0.53`** — этот пир и есть DNS-сервер. Оставь у него пустое поле или `127.0.0.1`. Если поставить `10.10.0.53` и при старте wg-quick попытается прописать его в `/etc/resolv.conf` внутри контейнера ДО того, как CoreDNS поднялся — получишь зависший резолв и таймауты.

---

## Шаг 11. Регистрация trust anchor у клиентов

Внутренний CA — приватный, его корневой сертификат браузеры и системы не знают. Чтобы https://acme.lan.vpn:8443/ открывался без warning'ов, корень надо доставить на каждый клиент.

### 11.1. Положить корень на сервисную машину

Скопируй `cert.pem` из CA-контекста в публичную папку CoreDNS (если хочешь раздавать его прямо отсюда — но CoreDNS не сервер для HTTP). Проще — отдавать его через ACME-сервер:

В `acme/config/config.yaml`:

```yaml
public_endpoints:
  - path: /root.crt
    file: /secutor/context/cert.pem
    content_type: application/x-pem-file
```

(Если такой опции в secutor-acme нет — поставь рядом маленький nginx-контейнер в том же namespace, отдающий статику.)

### 11.2. На Linux-клиенте

```bash
sudo curl -fsSL http://acme.lan.vpn/root.crt -o /usr/local/share/ca-certificates/internal-root.crt
sudo update-ca-certificates
```

### 11.3. На macOS

```bash
curl -fsSL http://acme.lan.vpn/root.crt -o /tmp/internal-root.crt
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/internal-root.crt
```

### 11.4. На Windows

Скачать `root.crt`, открыть, «Установить сертификат» → «Локальный компьютер» → «Доверенные корневые центры сертификации».

После этого `curl https://acme.lan.vpn:8443/directory` (без `-k`) должен работать без ошибок TLS.

---

## Бэкапы

Что критично:

| Файл/том | Что внутри | Можно ли потерять |
|---|---|---|
| `acme/context/` | Зашифрованный приватный ключ CA, сертификат | **Нет.** Потеря = всем сертификатам конец. |
| `acme/secrets/context_password.txt` | Пароль контекста | **Нет.** Без него `context/` бесполезен. |
| `secutor-acme-data` (named volume) | БД ACME, аккаунты клиентов, журнал выпусков | Очень нежелательно. Восстановимо, но клиенты заново зарегистрируются. |
| `coredns/zones/lan.vpn.zone` | Зона DNS | Восстановимо руками. |
| `wg/wg0.conf` | Приватный ключ WG-клиента | Можно перевыпустить через wg-portal. |

### Скрипт бэкапа

`/etc/cron.daily/services-backup`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR=/var/backups/services
DATE=$(date +%F)
mkdir -p "$BACKUP_DIR"

# горячий бэкап БД secutor-acme через docker
docker run --rm \
  -v services_secutor-acme-data:/data:ro \
  -v "$BACKUP_DIR":/backup \
  alpine \
  sh -c "cp /data/acme.db /backup/acme-$DATE.db"

# архив всей сервисной папки (КРОМЕ data — она уже выгружена выше)
tar czf "$BACKUP_DIR/services-$DATE.tgz" \
  --exclude='acme/data' \
  -C /home/admin services

# ротация
find "$BACKUP_DIR" -name "*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "services-*.tgz" -mtime +30 -delete
```

```bash
sudo chmod +x /etc/cron.daily/services-backup
sudo /etc/cron.daily/services-backup     # тестовый прогон
```

**Самое важное** — `acme/context/` и пароль. Положи их в отдельное офлайн-хранилище (например, зашифрованный USB в сейф). Если потеряешь — придётся выпускать новый CA и перевыпускать все клиентские сертификаты.

### Восстановление

```bash
cd ~/services
docker compose down

# восстанавливаем БД
docker run --rm \
  -v services_secutor-acme-data:/data \
  -v /var/backups/services:/backup:ro \
  alpine \
  sh -c "cp /backup/acme-YYYY-MM-DD.db /data/acme.db"

# восстанавливаем файлы
tar xzf /var/backups/services/services-YYYY-MM-DD.tgz -C /home/admin/

docker compose up -d
```

---

## Обновление сервисов

```bash
cd ~/services

# смотрим, что доступно
docker compose pull

# применяем — поднимет новые образы, старые контейнеры заменит
docker compose up -d

# смотрим логи
docker compose logs --tail=100 -f
```

**Правила**:
- Перед обновлением — бэкап (см. выше). Всегда.
- Версии образов в compose **зафиксированы** (`coredns:1.11.3`, `secutor-acme:1.0.0`). При обновлении меняй тег вручную и читай changelog.
- Если apply сломал что-то — откат:
  ```bash
  # верни старый тег в docker-compose.yml
  docker compose up -d
  ```

---

## Альтернатива: BIND с TSIG для DNS-01 challenge

CoreDNS из коробки **не поддерживает динамические DNS-обновления через RFC 2136 (DDNS)**. Это значит: если ты хочешь использовать **DNS-01 challenge** в ACME, где клиент (или сам ACME-сервер) должен добавлять `_acme-challenge.*` TXT-записи на лету — CoreDNS не подойдёт.

В этом случае замени `coredns` на `bind9` с настроенным TSIG-ключом. Конфиг детально расписан в [vpn-setup.md, раздел про BIND](vpn-setup.md). Compose будет таким:

```yaml
services:
  wg:
    # как выше

  bind:
    image: internetsystemsconsortium/bind9:9.18
    network_mode: "service:wg"
    depends_on:
      wg: { condition: service_healthy }
    volumes:
      - ./bind/named.conf:/etc/bind/named.conf:ro
      - ./bind/zones:/etc/bind/zones
      - ./bind/keys:/etc/bind/keys:ro
    restart: unless-stopped

  acme:
    # как выше, но с указанием TSIG-ключа
    environment:
      ...
      SECUTOR_DNS_RFC2136_KEY_FILE: /run/secrets/dns_rfc2136_key
      SECUTOR_DNS_RFC2136_SERVER: 127.0.0.1:53
    secrets:
      - context_password
      - dns_rfc2136_key
```

Конкретный `named.conf` + генерация TSIG-ключа — в [vpn-setup.md](vpn-setup.md). Дублировать здесь не буду — там это уже расписано детально.

**Решение**:
- Если ACME у тебя использует **только** `tls-alpn-01` и/или `http-01` — оставайся на CoreDNS.
- Если нужен `dns-01` (например, для wildcard-сертификатов или для бэкендов, не открытых наружу) — переходи на BIND.

---

## Мониторинг

### Метрики

| Сервис | Эндпоинт | Что мониторить |
|---|---|---|
| CoreDNS | `:9153/metrics` | `coredns_dns_requests_total`, `coredns_dns_responses_total` по rcode, `coredns_cache_*` |
| ACME (secutor) | `:9100/metrics` | счётчики выпусков, отказов, latency валидации |
| wg | через `wg show` | handshake age, transfer rate |

Скрейп с Prometheus (на хабе или где у тебя мониторинг):

```yaml
scrape_configs:
  - job_name: services-coredns
    static_configs:
      - targets: ['10.10.0.53:9153']

  - job_name: services-acme
    static_configs:
      - targets: ['10.10.0.53:9100']
```

### Алерты

```yaml
- alert: DNSResolverDown
  expr: up{job="services-coredns"} == 0
  for: 2m
  labels: { severity: critical }
  annotations:
    summary: "CoreDNS на сервисном пире недоступен"

- alert: ACMEDown
  expr: up{job="services-acme"} == 0
  for: 2m
  labels: { severity: critical }

- alert: HighDNSErrorRate
  expr: rate(coredns_dns_responses_total{rcode!="NOERROR",rcode!="NXDOMAIN"}[5m]) > 1
  for: 10m
  labels: { severity: warning }
```

### Логи

```bash
# поток
docker compose logs -f

# только ошибки coredns
docker compose logs coredns | grep -E "error|fail"

# аудит выпусков secutor
docker compose exec acme cat /var/log/secutor/audit.log
```

Для централизации — `logging.driver: loki` или `json-file` с забором через promtail.

---

## Типичные грабли

### `iface wg0 not found` или `cannot exec ...` при старте coredns/acme

`network_mode: "service:wg"` требует, чтобы `wg` уже был запущен и здоров. Проверь `depends_on` и `healthcheck`. Если healthcheck не настроен — coredns стартует раньше wg и падает.

### `bind: address already in use` для 53

Внутри namespace 53 уже занят. Скорее всего, на хост-системе работает `systemd-resolved`, и при `network_mode: host` он бы конфликтовал. У нас `service:wg`, не host, так что не должно быть, но если запускаешь wg-контейнер в режиме host — отключи resolved:
```bash
sudo systemctl disable --now systemd-resolved
```

### С хаба `dig @10.10.0.53 ...` не отвечает

1. Туннель установлен? `docker compose exec wg wg show` — handshake свежий?
2. На хабе iptables разрешает FORWARD между пирами? `sudo iptables -L FORWARD -v -n`, ищи правило `wg0 -> wg0 ACCEPT`.
3. Между хабом и сервисным пиром есть пинг? `ping 10.10.0.53` с хаба.

### `getaddrinfo: name or service not known` внутри acme-контейнера

ACME-сервер не может разрешить имя. CoreDNS, видимо, ещё не поднялся, а ACME уже стартовал. Проверь `depends_on: coredns`. Если уже стоит — увеличь `start_period` в healthcheck wg.

### CoreDNS не подхватывает изменения в zone-файле

- Проверь, что увеличил `serial` в SOA.
- В `Corefile` директива `reload 30s` — должна быть. Подожди 30 секунд после правки.
- Принудительный reload: `docker compose restart coredns`.

### secutor-acme не стартует: `failed to unlock context: invalid password`

`acme/secrets/context_password.txt` либо не тот пароль, либо с лишним переводом строки. Проверь:
```bash
xxd acme/secrets/context_password.txt | tail
# не должно быть 0a в конце
echo -n "правильный-пароль" > acme/secrets/context_password.txt
```

### Сертификат на `acme.lan.vpn` не валиден на клиенте

Не установлен корневой сертификат CA на этой машине. См. [Шаг 11](#шаг-11-регистрация-trust-anchor-у-клиентов).

### Часовое смещение → ACME nonce errors

ACME-сервер строго проверяет timestamps. Если на сервисной машине системное время сильно расходится с клиентом — будут ошибки. Поставь NTP:
```bash
sudo apt install chrony
sudo systemctl enable --now chrony
chronyc tracking
```

---

## Чек-лист перед уходом в прод

- [ ] Пир `services-dns-acme` создан в wg-portal с фиксированным `10.10.0.53/32` и PSK.
- [ ] У этого пира в wg-portal **DNS пустой или `127.0.0.1`**, не `10.10.0.53` (иначе курица-яйцо).
- [ ] `wg/wg0.conf` лежит с правами `600`.
- [ ] `acme/secrets/context_password.txt` — `600`, без перевода строки в конце.
- [ ] `acme/context/` — read-only bind-mount, владелец — `root` или совпадает с тем, под кем работает контейнер.
- [ ] CoreDNS отвечает на `dig @10.10.0.53 acme.lan.vpn` с хаба.
- [ ] ACME отвечает на `curl https://acme.lan.vpn:8443/directory` с хаба.
- [ ] У интерфейса `wg0` в wg-portal **Peer Defaults DNS** обновлён на `10.10.0.53`.
- [ ] У всех существующих пиров перевыпущены конфиги с новым DNS.
- [ ] Корневой сертификат CA установлен на админских машинах.
- [ ] Бэкап-скрипт настроен в крон, протестирован.
- [ ] Образы зафиксированы по версии, не `latest`.
- [ ] Prometheus скрейпит CoreDNS и ACME, алерты активны.
- [ ] Время на сервисной машине синхронизировано (NTP/chrony).
- [ ] План восстановления при потере CA задокументирован (где лежит резервная копия `context/` и пароль).
- [ ] `acme/context/` и пароль лежат в отдельном офлайн-хранилище (USB в сейфе, password manager).

---

## Связанные документы

- [ca-lifecycle.md](ca-lifecycle.md) — **обязательно прочитать перед прод-запуском**. Создание root + intermediate, бэкапы, доставка trust anchor, ротация, отзыв.
- [vpn-setup.md](vpn-setup.md) — оригинальная схема с DNS/ACME на хабе. Используй, если выбрал вариант A.
- [wg-portal-hub.md](wg-portal-hub.md) — настройка хаба, где регистрируется сервисный пир.
- [wg-interconnect.md](wg-interconnect.md) — топологии VPN, site-to-site, обратные маршруты.
- [wg-traefik-client-setup.md](wg-traefik-client-setup.md) — клиентская сторона с Traefik. Тот же паттерн `network_mode: service:wg`, что и здесь.
- [deployment.md](deployment.md) — деплой secutor-acme в общем виде, тома, секреты, env.
- [usage.md](usage.md) — как пользоваться ACME-сервером (выпуск сертификатов с клиента).
