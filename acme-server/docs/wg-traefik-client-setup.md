# WG-клиент + Traefik на клиентской машине

Подробный гайд для клиентской стороны: на машине уже работает **nginx** для пользователей из локальной сети, и нужно поднять рядом **WireGuard-клиент** в Docker, а за ним — **Traefik** как реверс-прокси, который будет получать сертификаты у внутреннего ACME-сервера через VPN и обслуживать запросы, приходящие со стороны VPN. nginx при этом остаётся как есть и ничего не ломается.

Гайд сквозной: с нуля до рабочего стека. Все примеры — с реальными значениями, можно копипастить и подставлять только свои ключи/домены.

## Содержание

- [Цель и предусловия](#цель-и-предусловия)
- [Что в итоге получится](#что-в-итоге-получится)
- [Архитектура и почему именно так](#архитектура-и-почему-именно-так)
- [Почему два других варианта не подходят](#почему-два-других-варианта-не-подходят)
- [Шаг 0. Подготовка хаба](#шаг-0-подготовка-хаба)
- [Шаг 1. Генерация ключей WireGuard на клиенте](#шаг-1-генерация-ключей-wireguard-на-клиенте)
- [Шаг 2. Структура файлов проекта](#шаг-2-структура-файлов-проекта)
- [Шаг 3. Конфиг WireGuard](#шаг-3-конфиг-wireguard)
- [Шаг 4. docker-compose.yml — построчно](#шаг-4-docker-composeyml--построчно)
- [Шаг 5. Trust anchor: корневой сертификат CA](#шаг-5-trust-anchor-корневой-сертификат-ca)
- [Шаг 6. DNS внутри VPN](#шаг-6-dns-внутри-vpn)
- [Шаг 7. Первый запуск](#шаг-7-первый-запуск)
- [Шаг 8. Проверка](#шаг-8-проверка)
- [Добавление новых сервисов](#добавление-новых-сервисов)
- [Расширения и опциональные блоки](#расширения-и-опциональные-блоки)
- [Типичные грабли](#типичные-грабли)
- [Чек-лист перед уходом в прод](#чек-лист-перед-уходом-в-прод)

---

## Цель и предусловия

**Цель**: разделить два потока трафика на одной клиентской машине.
- Пользователи из **локалки** (`192.168.1.0/24`) приходят на `https://<host-lan-ip>/...` — их обслуживает **nginx** на хосте, как было до этого.
- Сервисы и пользователи из **VPN** (`10.10.0.0/24`) приходят на `https://app.lan.vpn`, `https://api.lan.vpn` и т.п. — их обслуживает **Traefik** в Docker. Traefik получает TLS-сертификаты от ACME-сервера, который живёт на хабе VPN.

**Что должно быть готово до начала**:

1. На клиентской машине есть Docker и docker-compose v2 (`docker compose version` отвечает).
2. На клиенте уже работает nginx (на хосте или в Docker — не важно), и он слушает порты 80/443 на адресах локальной сети. **Это останется как есть.**
3. На хабе VPN:
   - Работает WireGuard-сервер на публичном IP, например `hub.example.com:51820`.
   - Работает ACME-сервер по адресу `acme.lan.vpn` (или другой DNS-имени), доступен только из VPN.
   - Работает внутренний DNS, который резолвит `*.lan.vpn`, отдавая адреса в `10.10.0.0/24`. Адрес DNS — `10.10.0.1`.
   - Известен публичный ключ хаба (`<hub_pub>`).
   - Известен корневой сертификат внутреннего CA (`hub-root.crt`).

Если что-то из этого не настроено — сначала разберись с хабом по [vpn-setup.md](vpn-setup.md), потом возвращайся сюда.

---

## Что в итоге получится

После выполнения всех шагов на клиенте будет работать:

- **Один WG-туннель** до хаба, IP клиента в VPN — `10.10.0.2`.
- **Traefik**, слушающий 80 и 443 **только** на интерфейсе `wg0` (то есть на `10.10.0.2`). На локалку он не торчит, конфликта портов с nginx нет.
- **Бэкенд-приложения** в Docker, доступные снаружи только через Traefik по HTTPS с валидными внутренними сертификатами.
- **Автоматическое продление** сертификатов через ACME, без ручных действий.

nginx как обслуживал `https://printer.lan` и `https://nas.lan` для локалки — так и продолжит.

---

## Архитектура и почему именно так

```
                 LAN 192.168.1.0/24
                       │
                       │  пользователи локалки
                       ▼
   ┌─────────────────────────────────────────┐
   │  Клиентский хост (192.168.1.50)         │
   │                                          │
   │   ┌──────────────────────────────────┐   │
   │   │ nginx (host network)              │   │
   │   │ listen 192.168.1.50:443           │   │   <── как было
   │   └──────────────────────────────────┘   │
   │                                          │
   │   ┌──────────────────────────────────┐   │
   │   │ Docker                            │   │
   │   │ ┌─────────────────────────────┐   │   │
   │   │ │ wg-контейнер                 │   │   │
   │   │ │  eth0  172.20.0.2 (bridge)   │◄──┼───┼── traefik сидит в этом же
   │   │ │  wg0   10.10.0.2  (VPN)      │   │   │   namespace и видит оба
   │   │ │                              │   │   │   интерфейса как свои
   │   │ │  слушает :80, :443 на wg0    │   │   │
   │   │ └─────────────────────────────┘   │   │
   │   │                                    │   │
   │   │ ┌──────┐  ┌──────┐  ┌──────────┐  │   │
   │   │ │ app  │  │ api  │  │ mon-srv  │  │   │
   │   │ │ :8080│  │ :3000│  │ :9090    │  │   │
   │   │ └──────┘  └──────┘  └──────────┘  │   │
   │   │   все в bridge "internal"          │   │
   │   └──────────────────────────────────┘   │
   └─────────────────────────────────────────┘
              │ wg0 туннель UDP/51820
              ▼
       VPN 10.10.0.0/24
              │
              ▼
   ┌────────────────────────────┐
   │ Hub (10.10.0.1)             │
   │  - WireGuard сервер          │
   │  - ACME (10.10.0.1:8443)     │
   │  - DNS (10.10.0.1:53)        │
   └────────────────────────────┘
```

**Ключевые идеи**:

1. **wg-контейнер подключён сразу к двум сетям**: к docker bridge `internal` (через него видит бэкенды) и к VPN через `wg0` (через него приходит трафик и уходит ACME-запрос на хаб).
2. **Traefik не имеет собственного network namespace** — он шарит namespace wg-контейнера через `network_mode: "service:wg"`. Это значит, что для Traefik `wg0` — такой же родной интерфейс, как и `eth0`. Он может на нём слушать порты, ходить наружу через туннель, всё прозрачно.
3. **Конфликта портов с хостовым nginx нет**, потому что Traefik слушает порты **внутри сетевого пространства wg-контейнера**, а не на хосте. На хост наружу никакие порты не пробрасываются.
4. **Бэкенды живут в обычном bridge**. Traefik видит их по docker-DNS (`http://app:8080`), потому что wg-контейнер тоже подключён к этому bridge, а Traefik сидит в его namespace.

---

## Почему два других варианта не подходят

Чтобы не повторять ошибок, которые часто встречаются:

### Вариант «всё в одном bridge, traefik рядом с wg»

```yaml
# Так НЕ работает:
services:
  wg: { ... networks: [internal] }
  traefik: { ... networks: [internal] }   # traefik в той же сети, но в СВОЁМ namespace
```

Traefik в своём namespace не видит `wg0`. У него собственный default route — наружу через docker-bridge → NAT хоста → публичный интернет. Никакой VPN-трафик через него не пойдёт, ACME-сервер по `10.10.0.1` он не найдёт. Bridge — это L2-связность между контейнерами, она не пробрасывает чужие туннели.

### Вариант «traefik как клиент, wg как gateway»

Технически можно: настроить wg-контейнер так, чтобы он работал как роутер (`ip_forward=1`, `MASQUERADE`), а у traefik прописать default gw = адрес wg-контейнера в bridge. Тогда трафик traefik → gw wg → wg0 → хаб.

Минусы:
- В docker-compose нельзя из коробки задать `default gw` контейнеру. Надо лезть в `cap_add: NET_ADMIN`, прописывать `ip route` в entrypoint.
- Нужны iptables-правила NAT на wg-контейнере.
- Если wg-контейнер перезапустился — у traefik default gw устаревает (другой IP).
- Дебажить запутаннее.

`network_mode: service:wg` решает всё это одной строкой и без NAT.

---

## Шаг 0. Подготовка хаба

Эта часть делается на **хабе** один раз. Если хаб уже настроен и тебе выдали готовые ключи — пропускай.

1. **Сгенерировать пару ключей для нового клиента** (на хабе или на любой машине):
   ```bash
   wg genkey | tee client.key | wg pubkey > client.pub
   wg genpsk > client.psk
   ```
   - `client.key` — приватный ключ клиента (отдать клиенту, никому больше).
   - `client.pub` — публичный ключ клиента (положить в `wg0.conf` хаба в секцию `[Peer]`).
   - `client.psk` — pre-shared key (положить **обеим сторонам**).

2. **На хабе** в `/etc/wireguard/wg0.conf` добавить секцию:
   ```ini
   [Peer]
   # клиент: офис-1
   PublicKey    = <содержимое client.pub>
   PresharedKey = <содержимое client.psk>
   AllowedIPs   = 10.10.0.2/32
   ```
   и перезагрузить:
   ```bash
   sudo wg syncconf wg0 <(wg-quick strip wg0)
   ```

3. **Передать клиенту три вещи** безопасным каналом:
   - его приватный ключ (`client.key`)
   - pre-shared key (`client.psk`)
   - публичный ключ хаба (`<hub_pub>`)
   - корневой сертификат CA (`hub-root.crt`) — про него ниже

---

## Шаг 1. Генерация ключей WireGuard на клиенте

Если ключи уже сгенерированы на хабе и тебе их выдали — пропускай. Если нет — на клиентской машине:

```bash
mkdir -p ~/wg-traefik/wg
cd ~/wg-traefik/wg

# приватный + публичный ключ
wg genkey | tee privatekey | wg pubkey > publickey
chmod 600 privatekey

cat publickey
# вывод отправь админу хаба, он добавит peer и пришлёт PSK
```

Все дальнейшие шаги — на клиентской машине.

---

## Шаг 2. Структура файлов проекта

Создай рабочий каталог. Финальная структура:

```
~/wg-traefik/
├── docker-compose.yml
├── wg/
│   ├── wg0.conf           # конфиг WireGuard
│   ├── privatekey         # приватный ключ клиента (chmod 600)
│   └── publickey
├── traefik/
│   ├── letsencrypt/       # storage для acme.json (создастся сам, права 600)
│   └── hub-root.crt       # корневой сертификат CA (если CA приватный)
└── apps/
    └── (опционально — конфиги бэкендов)
```

```bash
mkdir -p ~/wg-traefik/{wg,traefik/letsencrypt,apps}
cd ~/wg-traefik
```

---

## Шаг 3. Конфиг WireGuard

Файл `wg/wg0.conf`:

```ini
[Interface]
# IP клиента в VPN — /32 потому что мы клиент, а не роутер
Address    = 10.10.0.2/32
PrivateKey = <содержимое wg/privatekey>
# DNS внутри VPN — чтобы acme.lan.vpn резолвился
DNS        = 10.10.0.1

[Peer]
PublicKey    = <публичный ключ хаба>
PresharedKey = <pre-shared key, выданный админом>
Endpoint     = hub.example.com:51820
# ВАЖНО: только VPN-подсеть, иначе весь трафик клиента уйдёт в туннель
AllowedIPs   = 10.10.0.0/24
# держим туннель живым, важно если клиент за NAT
PersistentKeepalive = 25
```

Построчно:

- **`Address = 10.10.0.2/32`** — IP клиента в VPN. Маска `/32`, потому что клиент не представляет никакую подсеть, только сам себя. Если бы клиент был site-to-site гейтом — было бы шире, но это не наш случай.
- **`PrivateKey`** — содержимое `wg/privatekey`. Можно вместо этой строки использовать `PostUp = wg set %i private-key /etc/wireguard/privatekey`, но в `linuxserver/wireguard` проще оставить инлайн в конфиге, чтобы не танцевать с правами.
- **`DNS = 10.10.0.1`** — резолвер для туннеля. Поднимая `wg-quick`, контейнер пропишет этот DNS как системный, и внутри namespace `acme.lan.vpn` будет резолвиться правильно. Без этой строки Traefik не найдёт ACME-сервер по имени.
- **`AllowedIPs = 10.10.0.0/24`** — ровно VPN-подсеть, ничего лишнего. Если поставить `0.0.0.0/0`, **весь** трафик клиента (включая обычный интернет, включая трафик nginx-а на хосте!) пойдёт через туннель. Это почти всегда не то, что нужно.
- **`PersistentKeepalive = 25`** — раз в 25 секунд клиент шлёт пустой пакет на хаб, чтобы NAT-таблицы у провайдеров не закрыли «дыру». Без этого через ~5 минут простоя хаб не сможет инициировать пакет в сторону клиента.

**Поставь правильные права**:
```bash
chmod 600 wg/wg0.conf wg/privatekey
```

---

## Шаг 4. docker-compose.yml — построчно

Файл `docker-compose.yml`:

```yaml
networks:
  internal:
    driver: bridge

services:
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
    networks:
      - internal
    restart: unless-stopped
    # ports НЕ публикуем — все порты слушаются ВНУТРИ namespace

  traefik:
    image: traefik:v3.3       # v3.1 имеет баг с Docker API negotiation — см. типичные грабли
    container_name: traefik
    depends_on:
      wg:
        # ВАЖНО: именно service_healthy, не service_started — иначе Traefik
        # может стартовать раньше, чем wg-quick поднимет интерфейс с адресом
        # 10.x.x.x, и bind(10.x.x.x:80/443) упадёт с EADDRNOTAVAIL.
        condition: service_healthy
    network_mode: "service:wg"
    command:
      # === провайдер: автообнаружение сервисов по docker labels ===
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      # ВАЖНО: подставь РЕАЛЬНОЕ имя сети, не оставляй как есть.
      # Узнаётся через `docker network ls`. Формула: <имя-каталога-в-нижнем-регистре-без-дефисов>_<имя-сети-из-compose>
      # Пример: каталог "wg-traefik" → проект "wgtraefik" → сеть "wgtraefik_internal"
      - --providers.docker.network=wgtraefik_internal

      # === entrypoints: слушаем ТОЛЬКО на адресе wg0 ===
      - --entrypoints.web.address=10.10.0.2:80
      - --entrypoints.websecure.address=10.10.0.2:443

      # === HTTP → HTTPS редирект ===
      - --entrypoints.web.http.redirections.entrypoint.to=websecure
      - --entrypoints.web.http.redirections.entrypoint.scheme=https

      # === ACME через внутренний CA ===
      # ACME-эндпоинт по HTTPS — RFC 8555 §6.1 требует HTTPS, и lego (внутри
      # Traefik) откажется работать с plain HTTP. У secutor есть встроенный
      # TLS — см. dns-acme-peer.md, раздел "HTTP vs HTTPS".
      - --certificatesresolvers.hub.acme.email=admin@example.com
      - --certificatesresolvers.hub.acme.storage=/letsencrypt/acme.json
      # Если ACME живёт в ТОМ ЖЕ docker-compose (co-located), указывай 127.0.0.1:
      #   https://127.0.0.1:8443/directory
      # Если ACME на отдельной машине через VPN — по DNS-имени:
      - --certificatesresolvers.hub.acme.caserver=https://acme.lan.vpn:8443/directory
      # secutor поддерживает только http-01 и dns-01, НЕ tls-alpn-01.
      # tlschallenge=true даст "unsupported challenge type" при выпуске.
      - --certificatesresolvers.hub.acme.httpchallenge=true
      - --certificatesresolvers.hub.acme.httpchallenge.entrypoint=web

      # === логи, чтобы было что смотреть при дебаге ===
      - --log.level=INFO
      - --accesslog=true
    environment:
      # lego должен доверять root CA, который подписал bootstrap-cert секутора.
      # ca.pem отдаётся секутором по /ca.pem; скопируй один раз и подмонтируй сюда.
      - LEGO_CA_CERTIFICATES=/certs/hub-root.crt
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/letsencrypt:/letsencrypt
      - ./traefik/hub-root.crt:/certs/hub-root.crt:ro
    restart: unless-stopped

  # Пример бэкенда — простое веб-приложение
  app:
    image: nginxdemos/hello:plain-text
    container_name: app
    networks:
      - internal
    labels:
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`app.lan.vpn`)
      - traefik.http.routers.app.entrypoints=websecure
      - traefik.http.routers.app.tls=true
      - traefik.http.routers.app.tls.certresolver=hub
      - traefik.http.services.app.loadbalancer.server.port=80
    restart: unless-stopped
```

### Разбор по строчкам

**Сеть `internal`** — обычный docker bridge. Через неё wg-контейнер видит бэкенды (`app`, и любые другие, которые добавишь).

**Сервис `wg`**:

- `image: linuxserver/wireguard` — готовый образ, поднимает `wg-quick` из конфигов в `/config/wg_confs/`. Можно собрать свой, но этот работает «из коробки» и регулярно обновляется.
- `cap_add: NET_ADMIN, SYS_MODULE` — права нужны, чтобы создавать сетевой интерфейс и при необходимости подгружать модуль `wireguard` (на новых ядрах он уже встроен, но образ это проверяет).
- `sysctls.net.ipv4.conf.all.src_valid_mark` — нужно для маршрутизации внутри WG. Если забыть, получишь странные сообщения в логах wg-quick.
- `volumes: ./wg/wg0.conf:/config/wg_confs/wg0.conf:ro` — конфиг монтируется read-only. Если что-то поменял в нём — `docker compose restart wg`.
- **`ports` намеренно отсутствует** — мы не пробрасываем порты на хост. wg-контейнер слушает только UDP/51820 ИСХОДЯЩЕ, для входящего трафика порты не нужны (мы клиент).

**Сервис `traefik`**:

- `depends_on: wg` — Traefik не должен стартовать раньше wg, иначе при попытке привязаться к `10.10.0.2:443` получит «cannot assign requested address».
- **`network_mode: "service:wg"`** — главная строка. Traefik не получает собственный network namespace, а садится в namespace контейнера `wg`. Внутри он видит `eth0` (bridge `internal`) и `wg0` (VPN). Никакие `networks:` для Traefik указывать **не нужно и нельзя** — будет ошибка.
- `--providers.docker.network=wgtraefik_internal` — имя docker-сети **с префиксом проекта**. Если каталог называется `wg-traefik`, docker создаст сеть `wgtraefik_internal` (дефис убирается). Проверь свою: `docker network ls`. Этот параметр говорит Traefik «при обращении к бэкенду используй его IP в этой сети». Без него Traefik может выбрать неправильную сеть, если бэкенд подключён к нескольким.
- `--entrypoints.web.address=10.10.0.2:80` — биндимся на конкретный адрес. Если оставить `:80` без IP — Traefik забиндится на все интерфейсы внутри namespace, включая `eth0` (bridge), что не критично, но избыточно.
- `--certificatesresolvers.hub.acme.tlschallenge=true` — используется TLS-ALPN-01 challenge. Удобно, потому что ему нужен только 443 порт, который у нас уже открыт. Альтернативы: `httpchallenge` (нужен 80), `dnschallenge` (нужен API провайдера DNS).
- `LEGO_CA_CERTIFICATES` — переменная для `lego` (acme-клиент внутри Traefik), указывает путь к доверенному корневому сертификату. Без неё Traefik не доверяет приватному CA и ACME-запрос падает с x509 ошибкой.

**Сервис `app`**:

- Не публикует портов. Доступен только через Traefik.
- **Labels** — это декларативная конфигурация роута:
  - `traefik.enable=true` — без этого Traefik проигнорирует контейнер (мы выше включили `exposedbydefault=false`).
  - `Host(\`app.lan.vpn\`)` — Traefik роутит по HTTP-заголовку Host. DNS внутри VPN должен резолвить `app.lan.vpn` в `10.10.0.2`.
  - `entrypoints=websecure` — только через HTTPS (порт 443).
  - `tls.certresolver=hub` — использовать ACME-резолвер с именем `hub` (см. command Traefik выше).
  - `loadbalancer.server.port=80` — на какой порт контейнера слать запрос. У `nginxdemos/hello` это 80.

---

## Шаг 5. Trust anchor: корневой сертификат CA

> **Когда этот шаг нужен**: только если ACME-эндпоинт **по HTTPS** с приватным CA (схема B/C из [deployment.md](deployment.md#http-vs-https-на-acme-эндпоинте)). При HTTP-эндпоинте (схема A, дефолт) Traefik не делает TLS-handshake к ACME-серверу и в trust anchor для lego не нуждается — **пропусти этот шаг полностью**.
>
> Trust anchor на клиентских машинах (браузеры, curl) — другая история: он всегда нужен, чтобы клиенты доверяли **выпущенным** Traefik'ом сертификатам. Но это делается **на клиентах**, не на этой машине. Туда — см. [dns-acme-peer.md, Шаг 11](dns-acme-peer.md#шаг-11-регистрация-trust-anchor-у-клиентов).

Внутренний ACME-сервер обычно использует приватный корневой сертификат (не из Let's Encrypt или другого публичного CA). `lego` (ACME-клиент Traefik) по умолчанию работает только с публично доверенными CA — для приватного **по HTTPS** нужно явно дать ему корень.

1. Получи от админа хаба файл `hub-root.crt` в формате PEM:
   ```
   -----BEGIN CERTIFICATE-----
   MIIE...
   -----END CERTIFICATE-----
   ```

2. Положи в `traefik/hub-root.crt`.

3. В docker-compose это уже подключено:
   ```yaml
   environment:
     - LEGO_CA_CERTIFICATES=/certs/hub-root.crt
   volumes:
     - ./traefik/hub-root.crt:/certs/hub-root.crt:ro
   ```

Если CA-цепочка из нескольких сертификатов (root + intermediate) — склей их в один файл:
```bash
cat hub-root.crt hub-intermediate.crt > traefik/hub-root.crt
```

Скачать root прямо с ACME-эндпоинта секутора:
```bash
curl -fskL https://acme.lan.vpn:8443/ca.pem -o traefik/hub-root.crt
```
(`-k` для первого раза, потому что сертификат сервера сам подписан этим root'ом; после установки в trust store — без `-k`).

---

## Шаг 6. DNS внутри VPN

Traefik при запуске делает запрос к `https://acme.lan.vpn:8443/directory`. Чтобы это имя резолвилось, есть три пути:

1. **Через `DNS = 10.10.0.1` в `wg0.conf`** (рекомендую). `wg-quick` пропишет VPN-DNS как системный резолвер внутри namespace wg-контейнера. Это и для Traefik сработает, потому что он в том же namespace.

2. **Через `extra_hosts` в Traefik**, если на хабе нет DNS-сервера:
   ```yaml
   traefik:
     extra_hosts:
       - "acme.lan.vpn:10.10.0.1"
   ```
   Но если ты хочешь, чтобы и бэкенды (`app.lan.vpn`) тоже резолвились с других клиентов из VPN — DNS на хабе всё равно нужен.

3. **Через docker DNS-override**:
   ```yaml
   traefik:
     dns:
       - 10.10.0.1
   ```

Первый вариант предпочтительнее: одна точка настройки, всё работает по умолчанию.

---

## Шаг 7. Первый запуск

```bash
cd ~/wg-traefik

# проверим, что синтаксис compose ок
docker compose config

# скачиваем образы
docker compose pull

# стартуем
docker compose up -d

# смотрим логи WG, должен быть handshake
docker compose logs wg

# смотрим логи Traefik, должен быть запрос ACME и получение сертификата
docker compose logs -f traefik
```

В логах Traefik ищи строки:

```
Starting provider *acme.Provider
The ACME resolver "hub" is using HTTP challenge:
Server responded with a certificate.
```

Если видишь `Unable to obtain ACME certificate` — иди в [Типичные грабли](#типичные-грабли).

---

## Шаг 8. Проверка

### Туннель работает?

```bash
docker compose exec wg wg show
# latest handshake должен быть несколько секунд назад
# transfer должен расти при запросах
```

### Traefik слушает на правильном адресе?

```bash
docker compose exec wg ss -tlnp
# должно быть видно :80 и :443 на 10.10.0.2
# на 0.0.0.0 их быть НЕ должно
```

### ACME-сервер виден из namespace?

```bash
docker compose exec wg curl -v https://acme.lan.vpn:8443/directory --cacert /certs/hub-root.crt
# должен прийти JSON с endpoints
```

### Сертификат выписан?

```bash
ls -la traefik/letsencrypt/acme.json
# файл существует, размер > 1 KB
docker compose exec wg cat /letsencrypt/acme.json | jq '.hub.Certificates[].domain'
# должен показать app.lan.vpn
```

### Запрос с другой машины из VPN

С любого другого пира VPN:
```bash
curl -v https://app.lan.vpn
# должен прийти HTTP 200 с приветственной страницей nginxdemos/hello
# сертификат должен быть валидным (если на этой машине стоит hub-root.crt)
```

### nginx на LAN всё ещё работает?

С машины из локалки:
```bash
curl -v https://192.168.1.50/
# всё, как раньше — nginx обслуживает локалку
```

Если все четыре проверки зелёные — стек работает.

---

## Добавление новых сервисов

Чтобы добавить новый бэкенд за Traefik, просто добавь сервис в `docker-compose.yml`:

```yaml
  api:
    image: your-api:latest
    container_name: api
    networks:
      - internal
    labels:
      - traefik.enable=true
      - traefik.http.routers.api.rule=Host(`api.lan.vpn`)
      - traefik.http.routers.api.entrypoints=websecure
      - traefik.http.routers.api.tls=true
      - traefik.http.routers.api.tls.certresolver=hub
      - traefik.http.services.api.loadbalancer.server.port=3000
    restart: unless-stopped
```

`docker compose up -d api` — Traefik подхватит новый контейнер автоматически и выпустит сертификат на `api.lan.vpn`. **Не забудь добавить A-запись `api.lan.vpn → 10.10.0.2` на DNS-сервере хаба.**

### Бэкенды из других docker-compose стеков

Часто бэкенды (приложения) уже живут в отдельных docker-compose файлах — например, Vaultwarden, Planka, Nextcloud каждый в своём каталоге. Их **не нужно** перетаскивать в общий compose с wg+traefik. Достаточно подключить к одной shared сети.

Схема:

```
        ┌──────────────────────────────────┐
        │ docker network "vpn_internal"     │
        │ (external, создаётся один раз)    │
        └───┬────────────┬─────────────┬───┘
            │            │             │
   ┌────────▼─────┐ ┌────▼─────┐ ┌────▼──────┐
   │ services/    │ │ apps/    │ │ vaultwarden/│
   │  - wg         │ │ - planka │ │ - bitwarden │
   │  - traefik   │ │          │ │             │
   │  - acme      │ │          │ │             │
   └──────────────┘ └──────────┘ └─────────────┘
   (compose-стек 1)  (стек 2)     (стек 3)
```

**Шаг 1**. Создай сеть один раз (вне любого compose):

```bash
docker network create vpn_internal
```

**Шаг 2**. В compose с wg+traefik объяви как external:

```yaml
networks:
  internal:
    external: true
    name: vpn_internal

services:
  wg:
    networks: [internal]
  # traefik, coredns, acme — без networks: (наследуют от wg)
```

**Шаг 3**. В compose каждого бэкенда — то же самое:

```yaml
# планка/docker-compose.yml
networks:
  vpn:
    external: true
    name: vpn_internal

services:
  planka:
    networks: [vpn]
    labels:
      - traefik.enable=true
      - traefik.instance=vpn
      - traefik.docker.network=vpn_internal           # обязательно при множественных сетях
      - traefik.http.routers.planka.rule=Host(`planka.lan.vpn`)
      - traefik.http.routers.planka.entrypoints=websecure
      - traefik.http.routers.planka.tls.certresolver=hub
      - traefik.http.services.planka.loadbalancer.server.port=1337
```

После `docker compose up -d` в каждом каталоге проверь связность:

```bash
docker network inspect vpn_internal --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}'
# должны быть видны и wg, и planka, и остальные бэкенды
```

Traefik найдёт `planka` по docker-DNS на `vpn_internal` и будет проксировать на него.

**Важно**: на каждом бэкенде нужны:
- `traefik.instance=vpn` — фильтр constraints (см. раздел про множественные Traefik'и ниже).
- `traefik.docker.network=vpn_internal` — указывает Traefik'у, через какую сеть ходить (на случай, если бэкенд подключён к нескольким сетям).

---

## Расширения и опциональные блоки

### Traefik dashboard

Полезный веб-UI для просмотра роутов и состояния сертификатов. Добавь в `command`:

```yaml
      - --api.dashboard=true
      - --api.insecure=false
```

И отдельный роутер:

```yaml
    labels:
      - traefik.enable=true
      - traefik.http.routers.dashboard.rule=Host(`traefik.lan.vpn`)
      - traefik.http.routers.dashboard.entrypoints=websecure
      - traefik.http.routers.dashboard.tls.certresolver=hub
      - traefik.http.routers.dashboard.service=api@internal
      - traefik.http.routers.dashboard.middlewares=auth
      - traefik.http.middlewares.auth.basicauth.users=admin:$$2y$$10$$...
```

(Хэш пароля сгенерируй: `htpasswd -nB admin`. Доллары в YAML экранируются удвоением.)

### Middleware: IP-allowlist

Например, дашборд показывать только админам:

```yaml
      - traefik.http.middlewares.adminonly.ipallowlist.sourcerange=10.10.0.0/28
      - traefik.http.routers.dashboard.middlewares=adminonly,auth
```

### Несколько доменов на один бэкенд

```yaml
      - traefik.http.routers.app.rule=Host(`app.lan.vpn`) || Host(`app-alt.lan.vpn`)
```

### Wildcard-сертификат

Если внутренний ACME поддерживает DNS-01 challenge — можно выпустить `*.lan.vpn` одним сертификатом. Потребуется настроить DNS-провайдер в Traefik, в этом гайде не разворачиваю.

### Несколько Traefik'ов на одном хосте

Если на хосте уже работает другой Traefik (для публичных сервисов, легаси, или ещё для чего-то), и теперь ты добавляешь VPN-Traefik рядом — они оба видят **все** контейнеры на хосте через docker-socket и пытаются их роутить. Получается конфликт: чужие контейнеры с label'ами для другого Traefik'а попадают в наш и наоборот.

Симптом в логах:
```
WRN Could not find network named "..." for container "/foo"
ERR error="api is not enabled" routerName=dashboard@docker
```

Это означает «я подхватил labels чужого контейнера, но не могу их применить — он от другого Traefik'а».

**Решение — `constraints` по label**. Каждый Traefik фильтрует контейнеры по уникальной метке, остальные игнорирует.

В нашем VPN-Traefik:

```yaml
command:
  - --providers.docker.constraints=Label(`traefik.instance`,`vpn`)
```

В **другом** Traefik (если ты им управляешь — добавь то же самое со своим значением):

```yaml
command:
  - --providers.docker.constraints=Label(`traefik.instance`,`public`)
```

На бэкендах, которые должен брать VPN-Traefik:

```yaml
labels:
  - traefik.enable=true
  - traefik.instance=vpn          # ← фильтр для VPN-Traefik
  - traefik.http.routers.app.rule=Host(`app.lan.vpn`)
  - ...
```

Контейнер **без** правильного `traefik.instance` будет полностью проигнорирован — даже не залогируется warning. Так каждый Traefik видит только свой подмножество.

**Безопасности ради**: рассмотри [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) — фильтрующий прокси над docker.sock, отдающий каждому Traefik'у только разрешённые endpoint'ы. Тогда Traefik не может ни стартовать контейнеры, ни читать секреты, ни ходить в чужой neighbour'у. Связка constraints + socket-proxy — стандарт для multi-tenant хостов.

---

## Типичные грабли

### `cannot assign requested address` при старте Traefik

Traefik стартовал раньше wg, и `wg0` ещё не существует. Лечится:

```yaml
traefik:
  depends_on:
    wg:
      condition: service_healthy
wg:
  healthcheck:
    test: ["CMD", "wg", "show", "wg0"]
    interval: 5s
    timeout: 3s
    retries: 5
```

### `Unable to obtain ACME certificate: x509: certificate signed by unknown authority`

Вылетает только при HTTPS-варианте — `LEGO_CA_CERTIFICATES` не указан или файл не подмонтирован/пустой. Проверь:

```bash
docker compose exec wg cat /certs/hub-root.crt | head -1
# должно быть "-----BEGIN CERTIFICATE-----"
```

При HTTP-варианте этой ошибки в принципе не будет — Traefik не делает TLS-handshake к ACME-серверу.

### `urn:ietf:params:acme:error:incorrectResponse :: HTTP error: connect ECONNREFUSED <IP>:80`

ACME-сервер делает http-01 challenge — стучит на `http://<домен>/.well-known/acme-challenge/<token>`, и получает ECONNREFUSED. На указанном IP никто не слушает порт 80.

Самая частая причина — **race на старте**: Traefik стартует раньше, чем wg-quick поднимет `wg0` с адресом (например, `10.11.12.2`), и `bind(10.11.12.2:80)` падает с `EADDRNOTAVAIL`. Traefik живёт без entrypoint `web`. Лечится правильным `depends_on`:

```yaml
traefik:
  depends_on:
    wg:
      condition: service_healthy     # НЕ service_started
wg:
  healthcheck:
    test: ["CMD", "wg", "show", "wg0"]
    interval: 5s
    timeout: 3s
    retries: 5
```

Альтернатива — биндить на «все интерфейсы», тогда race не страшен:
```yaml
- --entrypoints.web.address=:80                # без явного IP
- --entrypoints.websecure.address=:443
```

Проверка:
```bash
docker compose exec wg ss -tlnp | grep -E ':(80|443)'
# должны быть оба порта — если только 443, web entrypoint не открылся
```

Если порты на месте, но challenge всё равно отбивается — проверь, что глобальный redirect web→websecure не съедает challenge-путь:
```bash
curl -v http://<домен>/.well-known/acme-challenge/test
# должно вернуться 404, а не 308 Permanent Redirect
```
Если редирект — поставь `permanent=false` или вынеси challenge на отдельный entrypoint.

### `Unable to obtain ACME certificate: unsupported challenge type "tls-alpn-01"`

В Traefik включён `tlschallenge=true`, а secutor поддерживает только **http-01** и **dns-01** (см. [`challenges.ts`](../src/server/challenges.ts)). Поменяй на http-01:

```yaml
- --certificatesresolvers.hub.acme.httpchallenge=true
- --certificatesresolvers.hub.acme.httpchallenge.entrypoint=web
```

Или dns-01 для wildcard (требует BIND с TSIG, см. [vpn-setup.md](vpn-setup.md)).

### `Unable to obtain ACME certificate: no such host: acme`

Traefik не может разрешить hostname `acme`. Это бывает, когда `acme`-контейнер тоже использует `network_mode: service:wg` — тогда docker-DNS не выдаёт для него имя, потому что у него нет собственного network namespace. Все контейнеры в одном namespace видят друг друга только через **127.0.0.1**.

Замени в `caserver` имя на loopback:
```yaml
- --certificatesresolvers.hub.acme.caserver=https://127.0.0.1:8443/directory
```

Это и есть «co-located» паттерн — самый прямой путь между контейнерами, шарящими namespace.

### `HTTPS is required` или `tls: failed to verify certificate` от ACME

Две родственные ошибки, оба означают рассогласование между секутором и Traefik'ом:

1. **`HTTPS is required: http://acme.lan.vpn:8443/directory`** — lego (внутри Traefik) принципиально не работает с plain HTTP по RFC 8555 §6.1. Включи HTTPS в секуторе через `SECUTOR_ACME_TLS_CERT`/`KEY` (см. [dns-acme-peer.md, bootstrap](dns-acme-peer.md#получение-bootstrap-сертификата-для-acmelanvpn)) и поменяй caserver на `https://`.

2. **`tls: failed to verify certificate: x509: certificate signed by unknown authority`** — секутор отвечает по HTTPS, но lego не доверяет root'у, которым подписан bootstrap-cert. Проброс root'а через `LEGO_CA_CERTIFICATES`:
   ```yaml
   environment:
     - LEGO_CA_CERTIFICATES=/certs/hub-root.crt
   volumes:
     - ./traefik/hub-root.crt:/certs/hub-root.crt:ro
   ```
   Файл качается с самого секутора: `curl -kL https://acme.lan.vpn:8443/ca.pem -o ./traefik/hub-root.crt`.

### Рассинхрон между `tls` и `baseUrl` в секуторе

Если в `config.yaml` секутора стоит `tls.{certFile,keyFile}` (HTTPS-слушатель), но `baseUrl: http://...` — секутор запустится, но в `/directory` будет отдавать `http://` URL'ы клиентам. lego начнёт ходить по ним и упрётся в TLS-handshake. Секутор при таком конфиге пишет в stderr `[secutor-acme] tls is configured but baseUrl is "..." (http://)`.

Лечение: `baseUrl` должен начинаться с `https://`, если включён встроенный TLS. И наоборот, при `baseUrl: https://...` без `tls` — конфиг для setup'а с внешним TLS-proxy.

### `404 not found` от ACME-сервера на `/acme/acme/directory`

У secutor directory лежит на `/directory`, без префикса `/acme/acme/`. Префикс `/acme/acme/` — это конвенция smallstep/step-ca, secutor её не использует.

Поправь URL:
```yaml
- --certificatesresolvers.hub.acme.caserver=https://acme.lan.vpn:8443/directory
```

### `Could not find network named "<префикс>_internal"` или `WRN Defaulting to first available network`

Два варианта причины:

1. **Литеральный плейсхолдер из доки**. Строка `<префикс>_internal` — это пример, его нужно заменить на реальное имя docker-сети. Узнай через `docker network ls` и подставь.

2. **Несколько Traefik'ов на хосте** видят чужие контейнеры. См. раздел [«Несколько Traefik'ов на одном хосте»](#несколько-traefikов-на-одном-хосте) выше — лечится через `constraints` по label.

### `error="api is not enabled" routerName=dashboard@docker`

Какой-то контейнер на хосте имеет label `traefik.http.routers.dashboard.*`, который попадает в наш Traefik, но у нас не включён `--api.dashboard=true`. Чаще всего это значит, что Traefik подцепил контейнер от **другого** Traefik-стека, в котором dashboard был сконфигурирован.

Решение — те же `constraints` по label (см. выше). После их добавления Traefik перестанет видеть чужие контейнеры и эта ошибка пропадёт.

### `client version 1.24 is too old. Minimum supported API version is 1.40`

Эта ошибка — про **Docker-провайдер** Traefik, не про ACME. Traefik не может прочитать docker-socket для автодискавери бэкендов. Сам ACME при этом обычно работает (`hub.acme` provider в логах ОК).

Причина: в старых релизах Traefik v3.x (включая v3.1) Docker SDK не делает version negotiation и шлёт API v1.24 (из 2016 года). Современные демоны (Docker 23+) требуют минимум 1.40.

**Решение А — обновить Traefik** (рекомендую):
```yaml
traefik:
  image: traefik:v3.3      # или новее
```
В v3.3+ авто-негоциация исправлена.

**Решение Б — пин API-версии через env**:
```yaml
traefik:
  environment:
    - DOCKER_API_VERSION=1.45
```
Узнать поддерживаемую демоном:
```bash
docker version --format '{{.Server.APIVersion}}'
```
Ставь значение **не выше** этого.

### `Unable to obtain ACME certificate: ... no such host`

DNS внутри namespace не резолвит `acme.lan.vpn`. Проверь:

```bash
docker compose exec wg cat /etc/resolv.conf
# должна быть строка "nameserver 10.10.0.1"
docker compose exec wg getent hosts acme.lan.vpn
```

Если резолва нет — проверь, что в `wg0.conf` стоит `DNS = 10.10.0.1`, и что в образе linuxserver/wireguard есть `resolvconf` (он там есть из коробки).

### `Provider docker error: network ... not found`

Имя docker-сети в `--providers.docker.network` не совпадает с реальным. Узнай:

```bash
docker network ls | grep internal
```

Подставь точное имя. Имя проекта = имя каталога в нижнем регистре без дефисов/подчёркиваний.

### Traefik слушает на 0.0.0.0 вместо 10.10.0.2

Забыл указать IP в `--entrypoints.X.address`. Проверь `docker compose exec wg ss -tlnp`. Если видишь `0.0.0.0:443` — порт торчит и на bridge `internal`. Не критично с точки зрения безопасности (на bridge кроме своих контейнеров никого), но избыточно.

### Handshake есть, а HTTPS не отвечает с другой машины VPN

Проверь, что на другой машине в `AllowedIPs` своего пира на хабе указано `10.10.0.0/24`, а не только `10.10.0.1/32`. Без этого пакеты к `10.10.0.2` уйдут не в туннель, а в default route.

### `wg0: Address already in use`

Где-то снаружи docker (на хосте?) тоже поднят WG с тем же IP. Используй разные подсети или гаси хостовый wg.

---

## Чек-лист перед уходом в прод

- [ ] Приватные ключи WG и PSK лежат с правами `600`, владелец — твой пользователь.
- [ ] `traefik/letsencrypt/acme.json` создан с правами `600` (Traefik сам это сделает, но проверь).
- [ ] Корневой сертификат `hub-root.crt` от админа CA, не самопальный.
- [ ] DNS-имена бэкендов добавлены на DNS-сервере хаба.
- [ ] `restart: unless-stopped` стоит у всех сервисов.
- [ ] Логи Traefik пишутся куда надо (по умолчанию stdout, забирает docker → journald).
- [ ] Включён `PersistentKeepalive` — если клиент за NAT.
- [ ] Backup `wg/`, `traefik/letsencrypt/` и `traefik/hub-root.crt` положен в безопасное место.
- [ ] nginx на хосте проверен: он по-прежнему обслуживает локалку и не сломался от появления Traefik.
- [ ] Прогнан `curl https://app.lan.vpn` с **другой** машины VPN, не с самого клиента.

---

## Что дальше

- Если нужно, чтобы Traefik слушал и на LAN тоже (один и тот же домен из локалки и из VPN) — это уже другая задача, придётся делить 443 с nginx через SNI-роутер (`sslh`, `nginx stream`) или перенести весь фронт в Traefik. См. отдельный гайд (TBD).
- Если на клиентской машине надо несколько WG-сетей одновременно — посмотри [wg-interconnect.md](wg-interconnect.md), раздел про несколько интерфейсов.
- Если ACME-сервер выпускает короткоживущие сертификаты (сутки-неделя) — настрой алерты на свежесть `acme.json` через Prometheus или blackbox-exporter.
