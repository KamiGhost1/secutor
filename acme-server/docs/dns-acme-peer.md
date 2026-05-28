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
- [Шаг 7.5. Права, uid и tmpfs — общая шпаргалка](#шаг-75-права-uid-и-tmpfs--общая-шпаргалка)
- [Гибридная схема: HTTP для ACME, HTTPS для всего остального](#гибридная-схема-http-для-acme-https-для-всего-остального)
- [Нужны ли Traefik labels на самом ACME-сервере?](#нужны-ли-traefik-labels-на-самом-acme-сервере)
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
- ACME-сервер слушает на `https://acme.lan.vpn:8443/directory`, доступен из всей VPN. Использует встроенный TLS секутора с bootstrap-сертификатом, выпущенным один раз через TUI — необходимо для совместимости с стандартными ACME-клиентами (lego/Traefik, certbot, acme.sh). Альтернативу с HTTP за внешним reverse-proxy см. в [HTTP vs HTTPS: что выбрать](#http-vs-https-что-выбрать).
- Все клиенты VPN получают `DNS = 10.10.0.53` через push из wg-portal.
- Корневой сертификат CA доступен скачиванием по `https://acme.lan.vpn:8443/ca.pem` (встроенный эндпоинт секутора).

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
        ├── store.enc                    # зашифрованная SQLite БД (одна на все CA)
        └── context.json                 # метаданные контекста (salt, итерации, верификатор)
```

### Установка прав

⚠️ **Важно**: директории и файлы требуют **разных** прав. Директории должны иметь бит `x` (execute), иначе ни одна программа не сможет «войти» в них и прочитать содержимое — даже если файлы внутри открыты на чтение. Поэтому **нельзя использовать `chmod -R 600` или `rsync --chmod=600`** на папках — они сломают все вложенные директории.

Правильно — раздельно файлы и директории:

```bash
cd ~/services

# === Секреты ACME: строго для владельца, никому больше ===
chmod 700  acme/secrets acme/data acme/context
chmod 600  acme/secrets/context_password.txt 2>/dev/null || true

# === Зоны и конфиг CoreDNS: не секрет, можно r-- всем ===
# CoreDNS работает от nonroot uid 65532 в distroless образе
chmod 755  coredns coredns/zones
chmod 644  coredns/Corefile coredns/zones/*.zone 2>/dev/null || true

# === WG-конфиг: содержит приватный ключ, строго 600 ===
chmod 700  wg
chmod 600  wg/wg0.conf 2>/dev/null || true

# === config.yaml для acme: не секрет (нет паролей внутри) ===
chmod 644  acme/config/config.yaml 2>/dev/null || true
```

### Доставка CA-контекста с админской машины

```bash
# с админской машины. ВАЖНО: только intermediate, не root!
# (root живёт оффлайн, см. ca-lifecycle.md)

# ВАРИАНТ 1: rsync с раздельным chmod для файлов и директорий (рекомендую)
rsync -av \
  --chmod=Du=rwx,Dg=,Do=,Fu=rw,Fg=,Fo= \
  ~/.secutor/contexts/intermediate/ \
  services-host:~/services/acme/context/

# ВАРИАНТ 2: обычный rsync без --chmod, потом руками поправить на сервере
rsync -av ~/.secutor/contexts/intermediate/ services-host:~/services/acme/context/
ssh services-host 'chmod 700 ~/services/acme/context && chmod 600 ~/services/acme/context/*'
```

Что делает `--chmod=Du=rwx,Dg=,Do=,Fu=rw,Fg=,Fo=`:
- `Du=rwx` — Directories User = `rwx` (700, есть `x` — можно войти).
- `Dg=,Do=` — Directories Group/Other = ничего.
- `Fu=rw` — Files User = `rw` (600).
- `Fg=,Fo=` — Files Group/Other = ничего.

Не используй `--chmod=600` или `--chmod=u=rw` без разделения на D и F — директории станут неюзабельными (без `x`), и `fs.existsSync` внутри контейнера будет возвращать `false` для всех файлов.

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

> **Reverse-зона (PTR) опциональна и НЕ показана здесь.** Если она тебе нужна (для `dig -x 10.10.0.53`), создай отдельный файл `coredns/zones/reverse.zone` с PTR-записями и добавь блок:
> ```caddy
> # для подсети 10.10.0.0/24 это будет 0.10.10.in-addr.arpa
> # для другой подсети считай так: байты сети в обратном порядке + .in-addr.arpa
> 0.10.10.in-addr.arpa:53 {
>     file /etc/coredns/zones/reverse.zone
>     errors
> }
> ```
> Использовать тот же файл, что и для прямой зоны, **нельзя** — там A-записи, а нужны PTR. Это разные форматы.

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
- **Комментарии в BIND zone-формате начинаются с `;`, а НЕ с `#`**. Строка `#alice IN A ...` НЕ комментарий — CoreDNS попытается разобрать её как запись с именем `#alice` и упадёт. Если копируешь шаблон с закомментированными примерами — закомментировано `;`.
- **Права файла должны позволять чтение пользователю, под которым работает CoreDNS** (в официальном образе `coredns/coredns:1.11.x` — это nonroot uid 65532). Достаточно `chmod 644 lan.vpn.zone` и `chmod 755` на содержащую папку. Zone-файлы — не секрет, их и так раздаёт DNS на любой запрос.

### 5.3. Автоматизация зоны (опционально)

Если устал руками держать зону в синхронизации с wg-portal — у wg-portal есть REST API и webhook-хуки. Можно написать маленький скрипт, который при создании пира в wg-portal автоматически добавляет A-запись в zone-файл и увеличивает serial. Образец — в [wg-portal-hub.md, шаг 10](wg-portal-hub.md#шаг-10-rest-api-и-автоматизация).

---

## Шаг 6. ACME-сервер (secutor-acme)

### HTTP vs HTTPS: что выбрать

ACME-протокол по RFC 8555 §6.1 **требует HTTPS** на directory-эндпоинте. Стандартные клиенты (lego в Traefik, certbot, acme.sh) откажутся работать с `http://` URL'ами. Поэтому в проде должен быть HTTPS.

Secutor поддерживает **два режима**:

| Режим | Как настроить | Когда брать |
|---|---|---|
| **HTTPS встроенный** (рекомендуется) | в `config.yaml` указать `tls.certFile` + `tls.keyFile` (либо env `SECUTOR_ACME_TLS_CERT` + `SECUTOR_ACME_TLS_KEY`). Secutor сам поднимает Fastify с TLS. | Базовый сценарий: один контейнер обслуживает и TLS, и ACME. |
| **HTTP за reverse proxy** | оставить `tls` пустым. Перед secutor поставить nginx/Traefik, который терминирует TLS. | Уже есть reverse proxy в стеке, хочется централизовать сертификаты в нём. |

В обоих случаях нужен **bootstrap-сертификат** для имени `acme.lan.vpn` — получить его через ACME нельзя (классическая курица-яйцо: ACME ещё не работает). Варианты получения:

1. **Через TUI секутора** (`secutor` CLI без аргументов): открыть контекст intermediate, выпустить сертификат на `acme.lan.vpn`, экспортировать в `.pem` файлы.
2. **Самоподписанный временный**: `openssl req -x509 ...`, плюс прокинуть свой root в `LEGO_CA_CERTIFICATES` Traefik'у. Подходит для PoC, не для прода.

После выпуска cert ротируется так же — за месяц до истечения выпустить новый, заменить файлы, секутор перечитает при рестарте (или можно повесить `SIGHUP` хук в будущем).

В дальнейших примерах используется **HTTPS встроенный** — это правильный путь.

### 6.1. config/config.yaml

`acme/config/config.yaml` (минимальный пример). Реальная схема живёт в [`acme-server/src/server/config.ts`](../src/server/config.ts), все поля ниже — оттуда, проверено по коду:

```yaml
# Адрес прослушивания. Перекрывается env SECUTOR_ACME_LISTEN.
listen: "0.0.0.0:8443"

# Публичный URL — попадает в /directory. Должен совпадать с реальной схемой
# (https:// если включён tls ниже; http:// только если перед secutor стоит
# внешний TLS-терминирующий прокси).
# Перекрывается env SECUTOR_ACME_BASE_URL.
baseUrl: "https://acme.lan.vpn:8443/"

# Контекст CA — путь к папке со store.enc + context.json.
# Перекрывается env SECUTOR_CONTEXT_DIR.
contextDir: /secutor/context

# Файл с паролем контекста. Перекрывается env SECUTOR_CONTEXT_PASSWORD_FILE.
contextPasswordFile: /run/secrets/context_password

# Какую CA-запись из контекста использовать для подписи.
# null = первая запись типа "ca" (если в контексте только intermediate — она).
caCertName: null

# БД состояния secutor. Перекрывается env SECUTOR_ACME_DB.
stateDb: /var/lib/secutor-acme/acme.db

# === Встроенный TLS ===
# Поднимает Fastify в HTTPS-режиме. ACME-клиенты (lego/Traefik, certbot, acme.sh)
# по RFC 8555 §6.1 требуют HTTPS — без этого они откажутся работать.
# Если оба пути не заданы — secutor слушает HTTP (только за reverse proxy).
#
# Эквивалентно env SECUTOR_ACME_TLS_CERT + SECUTOR_ACME_TLS_KEY (env wins
# при конфликте). Используй ОДИН источник, не оба — ниже в compose-примере
# я показываю вариант через env, можешь оставить так или перенести сюда.
# tls:
#   certFile: /secutor/tls/acme.lan.vpn.crt
#   keyFile:  /secutor/tls/acme.lan.vpn.key

# === DNS-резолверы для валидации challenge'ев ===
# Каждое правило: какие зоны через какие серверы. Первое подходящее правило выигрывает.
# "*" — fallback на любую зону.
resolvers:
  - zones: ["lan.vpn"]
    servers: ["127.0.0.1:53"]      # CoreDNS в том же namespace
  - zones: ["*"]
    servers: ["1.1.1.1", "8.8.8.8"]

# === Какие challenge'и поддерживаем ===
challenges:
  dns01: false             # включи только если есть BIND с TSIG (CoreDNS не поддерживает RFC2136)
  http01: true
  http01Port: 80           # порт, на который secutor стучится к домену при валидации http-01

# === Сроки ===
leafValidityDays: 90       # сколько живут выпускаемые сертификаты
nonceTtlSec: 600           # TTL ACME nonce
orderTtlSec: 604800        # TTL ACME-ордеров — 7 дней

# === Опциональный глобальный allow-list имён ===
# Если задан — все newOrder с именами вне списка отклоняются на уровне сервера,
# независимо от прав аккаунта. Безопасный дефолт для внутреннего CA.
allowList:
  dnsPatterns:
    - "*.lan.vpn"
```

> **Полей `issuance.*`, `logging.*`, `listen.acme/metrics`, `base_url` (snake_case) — нет в схеме**. Если в твоём `config.yaml` они есть — YAML-парсер их прочитает, но `loadConfig` их проигнорирует, и кода для них в секуторе тоже нет. Уровень логов задаётся через env `LOG_LEVEL=info|debug|trace` (читается Fastify в [`index.ts:32`](../src/server/index.ts)). Prometheus-метрик в текущей версии нет — мониторить через логи или внешний blackbox-exporter.

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
    # Переопределяем DNS-resolver на CoreDNS (127.0.0.1) внутри namespace.
    # По умолчанию Docker подсовывает 127.0.0.11 (embedded DNS), который не
    # знает про *.lan.vpn — Traefik и acme не смогут резолвить внутренние имена.
    # 1.1.1.1 — fallback на время старта, пока CoreDNS ещё не поднялся
    # (wg-quick резолвит свой Endpoint в этот момент).
    dns:
      - 127.0.0.1
      - 1.1.1.1
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
    # tmpfs обязательна при read_only: true — secutor-acme при загрузке
    # пишет распакованную SQLite во временный файл в /tmp и сразу удаляет.
    # Без tmpfs контейнер падает с EROFS.
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    environment:
      SECUTOR_CONTEXT_DIR: /secutor/context
      SECUTOR_CONTEXT_PASSWORD_FILE: /run/secrets/context_password
      SECUTOR_ACME_DB: /var/lib/secutor-acme/acme.db
      SECUTOR_ACME_CONFIG: /etc/secutor-acme/config.yaml
      SECUTOR_ACME_LISTEN: "0.0.0.0:8443"
      SECUTOR_ACME_BASE_URL: "https://acme.lan.vpn:8443/"
      # Bootstrap TLS — путь к cert/key для самого acme.lan.vpn (выпущенному
      # через TUI секутора, см. раздел "Получение bootstrap-сертификата").
      # Если оставить пустым — secutor поднимется как HTTP (только за reverse proxy).
      SECUTOR_ACME_TLS_CERT: /secutor/tls/acme.lan.vpn.crt
      SECUTOR_ACME_TLS_KEY:  /secutor/tls/acme.lan.vpn.key
    volumes:
      - type: bind
        source: ./acme/context
        target: /secutor/context
        read_only: true
      - ./acme/tls:/secutor/tls:ro                   # bootstrap cert+key
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
- `read_only: true` — корневая ФС read-only, всё запись идёт в volume `secutor-acme-data` или tmpfs.
- **`tmpfs: /tmp`** — обязательно при `read_only: true`. secutor-acme при загрузке пишет распакованную SQLite во временный файл в `/tmp` и сразу удаляет (см. [contextLoader.ts:113](../src/server/contextLoader.ts)). Без tmpfs контейнер падает с `EROFS`.
- **`SECUTOR_CONTEXT_DIR` не должен быть внутри `/tmp`** — иначе tmpfs перекроет bind-mount контекста. Используй `/secutor/context` или любой другой путь вне `/tmp`.
- `depends_on: coredns` — ACME при старте делает резолв своего же `base_url` для валидации; нужно, чтобы CoreDNS уже отвечал.
- CA-контекст подмонтирован read-only — секутор не должен иметь возможности туда писать.
- Пароль через docker secret, не env. См. [deployment.md, раздел Docker secrets](deployment.md).

---

## Шаг 7.5. Права, uid и tmpfs — общая шпаргалка

Самые частые причины «всё настроил, контейнер не стартует» в этой схеме — права на bind-mount файлы и взаимодействие `read_only` с tmpfs. Эта секция собирает всё это в одном месте, чтобы не натыкаться по очереди.

### Под каким uid работает каждый контейнер

| Контейнер | Образ | uid по умолчанию | Что важно |
|---|---|---|---|
| `wg` | `linuxserver/wireguard` | root (или PUID/PGID из env) | Создаёт сетевой интерфейс, нужен `cap_add: NET_ADMIN`. К bind-mount `wg0.conf` — без проблем. |
| `coredns` | `coredns/coredns:1.11.x` | **nonroot, uid 65532** (distroless образ) | Не может читать файлы с `chmod 600 root:root`. Файлы зон должны быть `chmod 644`, директории `chmod 755`. |
| `acme` | `secutor-acme` | зависит от Dockerfile, обычно root либо `node`/uid 1000 | Должен иметь право на чтение `/secutor/context/store.enc` и `/run/secrets/context_password`. |

Проверить, под кем реально работает процесс:

```bash
docker compose exec coredns id
docker compose exec acme id
docker compose exec wg id
```

### Шпаргалка по правам

| Файл/директория | Содержит | Права директории | Права файла | Кто читает |
|---|---|---|---|---|
| `acme/context/` | приватный ключ CA (зашифрован) | `700` | `600` | acme (если acme от root) |
| `acme/secrets/context_password.txt` | пароль для расшифровки | `700` (dir) | `600` | acme через docker secret |
| `acme/config/config.yaml` | конфиг ACME | `755` | `644` | acme |
| `coredns/Corefile` | конфиг DNS | `755` | `644` | coredns (uid 65532) |
| `coredns/zones/*.zone` | публичные DNS-записи | `755` | `644` | coredns |
| `wg/wg0.conf` | приватный ключ WG | `700` | `600` | wg (root) |

Главное правило: **если файл секретный → `600` + dir `700`. Если публичный → `644` + dir `755`.** На directory всегда нужен бит `x`, без него ничего внутри не работает.

### Команды для починки прав одним заходом

Если ты ранее уже наделал `chmod -R 600 ~/services` или `rsync --chmod=600` — вот восстановление:

```bash
cd ~/services

# секретные части
chmod 700 acme/secrets acme/context wg
chmod 600 acme/secrets/* acme/context/* wg/*

# публичные части
chmod 755 coredns coredns/zones acme/config
chmod 644 coredns/Corefile coredns/zones/*.zone acme/config/*.yaml

# data — secutor сам сюда пишет, нужно `rwx` для владельца, не критично
chmod 700 acme/data
```

### `read_only: true` и почему нужна tmpfs

Когда у контейнера стоит `read_only: true`, **вся корневая файловая система** контейнера становится недоступна на запись. Это включает:

- `/tmp` — обычно нужен node.js, python, многим runtime'ам.
- `/var/cache`, `/var/log`, `/run` — может быть нужно отдельным сервисам.

Если процесс попытается записать туда — получит `EROFS: read-only file system`.

Лечится монтированием **tmpfs** на нужные пути — это RAM-диск, который существует только пока контейнер запущен:

```yaml
acme:
  read_only: true
  tmpfs:
    - /tmp:rw,noexec,nosuid,size=64m       # для secutor-acme — распаковка SQLite
    # - /var/cache:rw,size=16m             # если runtime требует
    # - /run:rw,size=8m                    # для PID-файлов и сокетов

  volumes:
    - secutor-acme-data:/var/lib/secutor-acme    # постоянный rw — БД ACME
    - ./acme/context:/secutor/context:ro          # read-only — bind-mount контекста
```

Опции tmpfs:
- `rw` — на запись (без этого нет смысла).
- `noexec` — нельзя запускать бинарники, защита от выполнения payload'а.
- `nosuid` — игнорировать suid/sgid биты, ещё одна защита.
- `size=NNm` — лимит. Без него tmpfs возьмёт половину RAM хоста.

### Конфликт tmpfs и bind-mount: не клади контекст в `/tmp`

Если `SECUTOR_CONTEXT_DIR=/tmp/context` и одновременно `tmpfs: - /tmp:...` — tmpfs **перекрывает** содержимое `/tmp` целиком, твой bind-mount контекста становится невидим. Получишь `No store.enc or store.db`.

Правильно — путь контекста **вне** `/tmp`:

```yaml
environment:
  SECUTOR_CONTEXT_DIR: /secutor/context     # ✅ путь вне /tmp
volumes:
  - ./acme/context:/secutor/context:ro      # ✅ соответствует
tmpfs:
  - /tmp:rw,noexec,nosuid,size=64m          # ✅ для временных файлов
```

### Сводный чек-лист

Перед `docker compose up`:

- [ ] На `acme` стоит `read_only: true` **и** `tmpfs: - /tmp:...` (одно без другого не работает).
- [ ] `SECUTOR_CONTEXT_DIR` указывает на путь **вне `/tmp`** (например, `/secutor/context`).
- [ ] Bind-mount `acme/context` имеет права `700` (директория) и `600` (файлы внутри).
- [ ] Bind-mount `coredns/zones` имеет права `755` (директория) и `644` (файлы внутри), даже если файлы создавались rsync'ом.
- [ ] `acme/secrets/context_password.txt` — `600`, без `\n` в конце (`xxd ... | tail` показывает не `0a` последним).
- [ ] У `acme/context/` лежат именно `store.enc` и `context.json` (не `cert.pem` отдельно, не вложенная папка).

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
acme     | {"level":"info","scheme":"https","msg":"secutor-acme ready — listening HTTPS on 0.0.0.0:8443, signing as ..."}
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
# с самой сервисной машины (co-located доступ — самый быстрый путь)
# -k нужно, если root CA ещё не установлен в системный trust store
docker compose exec wg curl -sk https://127.0.0.1:8443/directory | jq

# с хаба или любого пира через VPN
curl -sk https://acme.lan.vpn:8443/directory | jq
# либо с установленным root CA — без -k:
curl -s https://acme.lan.vpn:8443/directory | jq
```

Должен прийти JSON с `newAccount`, `newOrder`, `newNonce` и т.п.

### 9.5. Метрики CoreDNS

CoreDNS экспортирует Prometheus-метрики на `:9153/metrics` (включено в Corefile через `prometheus :9153`):

```bash
docker compose exec wg curl -s http://127.0.0.1:9153/metrics | head
```

ACME-сервер (secutor) в текущей версии **Prometheus-метрики не экспортирует** — кода нет ни в `routes.ts`, ни в зависимостях. Мониторить можно через:
- логи (`docker compose logs acme`, `audit_log` таблица в `acme.db`);
- внешний blackbox-exporter, который проверяет `GET /directory`;
- ручной алерт на свежесть `acme.json` Traefik'а (отсутствие обновлений = выпуск сломан).

---

## Гибридная схема: ACME напрямую, Traefik для всего остального

Этот раздел — про правильный архитектурный паттерн, когда на той же машине, что и acme, работает **Traefik как reverse proxy для всех остальных сервисов VPN** (включая wg-portal на хабе, бэкенды в docker и сервисы из других compose-стеков).

### Идея

```
   VPN client (remote)
   │
   ├─► https://wg.lan.vpn         ──► Traefik :443 ─► hub:8888 (wg-portal)
   ├─► https://app.lan.vpn        ──► Traefik :443 ─► docker container
   ├─► https://vault.lan.vpn      ──► Traefik :443 ─► external compose
   │
   └─► https://acme.lan.vpn:8443  ──► acme :8443      [НЕ через Traefik]
        (TLS встроенный, bootstrap-cert выпущен через TUI секутора)

   Traefik получает свои сертификаты:
   Traefik ─► https://127.0.0.1:8443 ─► acme        [loopback внутри namespace]
   (lego доверяет bootstrap-cert'у потому, что он подписан intermediate CA,
    которому Traefik доверяет через LEGO_CA_CERTIFICATES = ca.pem)
```

**ACME-эндпоинт по HTTPS** (встроенный TLS секутора с одноразовым bootstrap-сертификатом). **Все остальные сервисы — HTTPS через Traefik** с сертификатами, выпускаемыми ACME автоматически. Bootstrap-cert обновляется раз в год через TUI.

### Что нужно в Traefik

К базовому конфигу из [wg-traefik-client-setup.md](wg-traefik-client-setup.md) добавь **file provider** для сервисов, которые не в docker (типичный пример — wg-portal на хабе):

```yaml
command:
  # docker provider — для бэкендов в docker-compose
  - --providers.docker=true
  - --providers.docker.exposedbydefault=false
  - --providers.docker.network=vpnnet
  - --providers.docker.constraints=Label(`traefik.instance`,`vpn`)

  # file provider — для сервисов на других машинах через VPN
  - --providers.file.filename=/etc/traefik/dynamic.yml
  - --providers.file.watch=true

  # ACME через loopback к локальному secutor по HTTPS (RFC 8555 §6.1 — lego
  # требует HTTPS, plain HTTP не примет). Bootstrap cert у secutor должен
  # быть подписан intermediate, и его публичный root доступен через /ca.pem.
  - --certificatesresolvers.hub.acme.caserver=https://127.0.0.1:8443/directory
  - --certificatesresolvers.hub.acme.httpchallenge=true
  - --certificatesresolvers.hub.acme.httpchallenge.entrypoint=web
environment:
  # lego должен доверять root CA, который подписал bootstrap-cert secutor'а
  - LEGO_CA_CERTIFICATES=/certs/ca.pem
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
  - ./traefik/letsencrypt:/letsencrypt
  - ./traefik/dynamic.yml:/etc/traefik/dynamic.yml:ro
  - ./acme/tls/ca.pem:/certs/ca.pem:ro              # root CA от секутора
```

### traefik/dynamic.yml для wg-portal

wg-portal живёт **на хабе**, не в локальном compose. Через docker provider его не увидеть, но file provider справляется:

```yaml
http:
  routers:
    wg-portal:
      rule: "Host(`wg.lan.vpn`)"
      entryPoints: [websecure]
      service: wg-portal
      tls:
        certResolver: hub

  services:
    wg-portal:
      loadBalancer:
        servers:
          - url: "http://10.11.12.1:8888"     # IP хаба в VPN + порт wg-portal
        passHostHeader: true
```

Что произойдёт при первом запросе:

1. Traefik видит router `wg-portal`, запрашивает cert для `wg.lan.vpn` у hub resolver'а.
2. Resolver идёт по `https://127.0.0.1:8443/directory` → к локальному ACME (lego доверяет bootstrap-cert'у благодаря `LEGO_CA_CERTIFICATES=/certs/ca.pem`) → запускает http-01 challenge.
3. ACME делает запрос `http://wg.lan.vpn/.well-known/acme-challenge/<token>`. DNS отдаёт `10.11.12.2` (наш Traefik). Traefik на entrypoint `web:80` отвечает challenge'у.
4. Cert выписан, Traefik начинает обслуживать `https://wg.lan.vpn`.
5. Запрос клиента: `https://wg.lan.vpn` → Traefik (TLS термина) → `http://10.11.12.1:8888` (wg-portal на хабе через WG-туннель).

### Конфиг wg-portal на хабе

В этой схеме wg-portal **больше не нужен свой nginx с TLS** — Traefik делает термин из другого хоста. На хабе в `~/wg-portal/config/config.yaml`:

```yaml
web:
  listening_address: "10.11.12.1:8888"     # слушаем на VPN-IP хаба, доступно для Traefik
  external_url: https://wg.lan.vpn          # URL для писем/QR — пользователи видят это
```

`external_url` остаётся `https://...`, потому что это то, что **видят пользователи**. `listening_address` — это **внутренний** адрес, по которому Traefik подключится (HTTP, без TLS, через VPN).

### DNS-зона

В `coredns/zones/lan.vpn.zone`:

```dns
ns          IN  A     10.11.12.2
acme        IN  A     10.11.12.2     ; прямой доступ к acme на :8443
hub         IN  A     10.11.12.1     ; именно хаб (для админских SSH)
wg          IN  A     10.11.12.2     ; через Traefik!
app         IN  A     10.11.12.2     ; через Traefik
vault       IN  A     10.11.12.2     ; через Traefik
```

**Ключевая деталь**: `wg.lan.vpn` указывает на `10.11.12.2` (где Traefik), а **не** на `10.11.12.1` (где сам wg-portal). Клиенты идут в Traefik, Traefik — в wg-portal.

### Что получает клиент

| URL | Куда идёт | Шифрование |
|---|---|---|
| `https://wg.lan.vpn` | Traefik :443 → hub:8888 | TLS (от внутреннего CA) + WG |
| `https://app.lan.vpn` | Traefik :443 → container | TLS + bridge |
| `https://vault.lan.vpn` | Traefik :443 → external compose | TLS + bridge через external network |
| `https://acme.lan.vpn:8443/directory` | напрямую acme | TLS (bootstrap cert) + JWS + WG |

### Преимущества

1. **Никакой курицы-яйца** для ACME — он на HTTP с момента старта.
2. **Один Traefik** обслуживает всю VPN — backends в docker + сервисы на других машинах (через file provider).
3. **wg-portal не требует nginx** на хабе — Traefik делает термин из соседней машины.
4. **Trust anchor (root CA)** клиентам нужен только для нормальных сервисов; для ACME — не нужен.
5. **Расширяемость**: новый сервис добавляется либо labels (если docker), либо строкой в `dynamic.yml` (если внешний).

---

## Нужны ли Traefik labels на самом ACME-сервере?

Частый вопрос: если в той же сборке есть Traefik, не надо ли и `acme`-контейнеру тоже выставить `traefik.enable=true` и роуты?

**По умолчанию нет.** Traefik не должен быть в цепочке запросов до ACME. Архитектура такая:

```
[remote VPN client] ──► https://acme.lan.vpn:8443/directory
                          │
                          ▼
                ┌──────────────────┐
                │ acme :8443       │ ← напрямую, без Traefik
                └──────────────────┘
```

Поскольку `acme` живёт в `network_mode: "service:wg"`, он слушает на `0.0.0.0:8443` **внутри namespace wg**. Это значит, что он автоматически доступен:
- **на `127.0.0.1:8443`** — для co-located Traefik и других сервисов в том же namespace;
- **на `10.11.12.2:8443`** (или какой у тебя VPN-IP сервисного пира) — для удалённых клиентов через WG-туннель;
- **только внутри VPN** — wg не пускает чужой трафик, на LAN/публичный интернет порт не торчит.

Никаких labels для этого не требуется, потому что **Traefik не задействован для маршрутизации к ACME**.

### Когда labels всё-таки нужны

Если по какой-то причине хочется проксировать ACME через Traefik (стандартный порт 443 вместо 8443, или TLS-терминация снаружи) — тогда добавь labels:

```yaml
acme:
  # ... всё как было, плюс:
  labels:
    - traefik.enable=true
    - traefik.instance=vpn
    - traefik.docker.network=vpnnet
    - traefik.http.routers.acme.rule=Host(`acme.lan.vpn`)
    - traefik.http.routers.acme.entrypoints=websecure
    - traefik.http.routers.acme.tls.certresolver=hub
    - traefik.http.services.acme.loadbalancer.server.port=8443
    - traefik.http.services.acme.loadbalancer.server.scheme=http
```

И поменяй `SECUTOR_ACME_BASE_URL` на `https://acme.lan.vpn/` (без `:8443`).

⚠️ **Проблема курицы и яйца**: Traefik должен получить cert на `acme.lan.vpn` от самого ACME через http-01 challenge. Пока этот цикл не пройдёт первый раз, HTTPS-эндпоинт не работает. Лечится bootstrap-выпуском через CLI:

```bash
secutor-cli issue --context intermediate --domain acme.lan.vpn --out /tmp/bootstrap.pem
# положить cert+key как статическую конфигурацию Traefik
```

⚠️ **Trust anchor требование расширяется**: при HTTPS-эндпоинте *все* ACME-клиенты должны иметь root CA в trust store **до** первого выпуска сертификата. При HTTP — root нужен только тем, кто принимает выпущенные сертификаты (браузеры, сервисы за Traefik).

Большинству инсталляций **вариант без проксирования проще, безопаснее и быстрее**. Лезть в Traefik имеет смысл только если есть конкретная причина — например, политика «всё на 443 за reverse proxy».

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

Внутренний CA — приватный, его корневой сертификат браузеры и системы не знают. Сам ACME-эндпоинт у нас идёт по HTTP (в схеме A — см. раздел [HTTP vs HTTPS](#http-vs-https-что-выбрать)), но **выпускаемые им сертификаты** клиенты ставят на свои сервисы и хотят, чтобы браузеры им доверяли. Для этого корень CA надо доставить на каждый клиент.

### 11.1. Где взять корень

Ничего настраивать не нужно — secutor отдаёт CA-сертификаты на встроенных эндпоинтах ([routes.ts:127-136](../src/server/routes.ts)):

| Endpoint | Что отдаёт |
|---|---|
| `GET /ca.pem` | **Root CA cert** (самоподписанный корень) — это и есть trust anchor для клиентов |
| `GET /chain.pem` | Intermediate-цепочка (если root отделён от signing CA) |
| `GET /crl.pem` | CRL в PEM |
| `GET /crl` | CRL в DER |

Так что качать root можно прямо с ACME-эндпоинта (первый раз — с `-k`, поскольку сертификат сервера сам подписан этим root'ом):
```bash
curl -k https://acme.lan.vpn:8443/ca.pem
```

### 11.2. На Linux-клиенте

```bash
sudo curl -fskL https://acme.lan.vpn:8443/ca.pem -o /usr/local/share/ca-certificates/internal-root.crt
sudo update-ca-certificates
```

### 11.3. На macOS

```bash
curl -fskL https://acme.lan.vpn:8443/ca.pem -o /tmp/internal-root.crt
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/internal-root.crt
```

### 11.4. На Windows

Скачать `https://acme.lan.vpn:8443/ca.pem` (через браузер, проигнорировать предупреждение TLS), переименовать в `*.crt`, открыть, «Установить сертификат» → «Локальный компьютер» → «Доверенные корневые центры сертификации».

После этого браузер на клиенте будет видеть зелёный замочек на сервисах, защищённых сертификатами от твоего внутреннего CA. (Сам ACME-эндпоинт по-прежнему по HTTP в схеме A — это нормально, TLS-доверие нужно для **выпущенных** сертификатов.)

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

CoreDNS из коробки **не поддерживает динамические DNS-обновления через RFC 2136 (DDNS)**. Это значит: если ты хочешь использовать **DNS-01 challenge**, при котором **клиент** ACME (acme.sh / certbot / lego на запрашивающей машине) должен добавлять `_acme-challenge.*` TXT-записи на лету через `nsupdate` — CoreDNS не подойдёт. Нужен BIND с настроенным TSIG-ключом.

Важно: сам **secutor-сервер** для dns-01 ничего на DNS не записывает — он только **читает** TXT-запись через свои resolver'ы (`config.resolvers`) и сравнивает с ожидаемым значением. То есть со стороны secutor-сервера никаких RFC2136-кредов не нужно, в его конфиге `config.ts` соответствующих полей нет. TSIG-ключ доставляется **клиенту**, который инициирует `nsupdate`.

Compose сервисной машины (где живёт acme-сервер):

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
      - ./bind/zones:/etc/bind/zones                # rw — для журналов dynamic update
      - ./bind/keys:/etc/bind/keys:ro
    restart: unless-stopped

  acme:
    # как и раньше. Никаких дополнительных env для DNS-01 НЕ нужно —
    # secutor только читает TXT через resolvers.
    # Включить dns01 в config.yaml:
    #   challenges:
    #     dns01: true
    #     http01: true       # можно оба
```

Конкретный `named.conf` + генерация TSIG-ключа — в [vpn-setup.md, раздел про BIND](vpn-setup.md). Там же — как этот TSIG-ключ доставлять клиенту и какие env-переменные нужны клиенту (например, для acme.sh `NSUPDATE_KEY=/path/to/key`).

**Решение**:
- Если у тебя только `http-01` — оставайся на CoreDNS (он у нас уже работает, без писательских функций).
- Если нужен `dns-01` (для wildcard-сертификатов или для сервисов, у которых нельзя открыть порт 80) — переходи на BIND.

---

## Мониторинг

### Метрики

| Сервис | Эндпоинт | Что мониторить |
|---|---|---|
| CoreDNS | `:9153/metrics` (Prometheus) | `coredns_dns_requests_total`, `coredns_dns_responses_total` по rcode, `coredns_cache_*` |
| ACME (secutor) | **нет Prometheus** — `GET /directory` через blackbox | живость эндпоинта, валидность response |
| wg | через `wg show` либо node_exporter | handshake age, transfer rate |

Скрейп CoreDNS с Prometheus:

```yaml
scrape_configs:
  - job_name: services-coredns
    static_configs:
      - targets: ['10.10.0.53:9153']

  # ACME — через blackbox_exporter, поскольку нативного /metrics нет
  - job_name: services-acme-blackbox
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets: ['http://10.10.0.53:8443/directory']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

### Алерты

```yaml
- alert: DNSResolverDown
  expr: up{job="services-coredns"} == 0
  for: 2m
  labels: { severity: critical }
  annotations:
    summary: "CoreDNS на сервисном пире недоступен"

- alert: ACMEEndpointDown
  expr: probe_success{job="services-acme-blackbox"} == 0
  for: 2m
  labels: { severity: critical }
  annotations:
    summary: "ACME /directory не отвечает"

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

### `lookup acme.lan.vpn on 127.0.0.11:53: no such host` (или другой `lan.vpn` not found из Traefik)

`/etc/resolv.conf` контейнеров указывает на embedded DNS Docker'а (`127.0.0.11`), а не на CoreDNS (`127.0.0.1:53`). Embedded DNS ничего не знает про `*.lan.vpn`.

Лечение — переопределить DNS на сервисе **`wg-client`** (контейнеры с `network_mode: "service:wg"` наследуют `/etc/resolv.conf` от него):

```yaml
wg-client:
  dns:
    - 127.0.0.1     # CoreDNS в том же namespace
    - 1.1.1.1       # fallback на время старта, пока CoreDNS не поднялся
```

⚠️ Прописывать `dns:` на `coredns`, `acme`, `traefik` **нельзя** — docker-compose выдаст ошибку. Конфиг сети у них наследуется.

Применить: `docker compose up -d --force-recreate wg-client`, потом перезапустить зависимые. Проверка:

```bash
docker compose exec wg cat /etc/resolv.conf
# должно быть: nameserver 127.0.0.1 / nameserver 1.1.1.1
docker compose exec wg nslookup acme.lan.vpn
# должно вернуть 10.11.12.2 от CoreDNS (Server: 127.0.0.1)
```

### CoreDNS не подхватывает изменения в zone-файле

- Проверь, что увеличил `serial` в SOA.
- В `Corefile` директива `reload 30s` — должна быть. Подожди 30 секунд после правки.
- Принудительный reload: `docker compose restart coredns`.

### `plugin/file: Failed to open zone ...: permission denied`

CoreDNS работает не от root и не может читать zone-файл. Сделай файл и папку с zone-файлами доступными на чтение всем:

```bash
chmod 755 coredns coredns/zones
chmod 644 coredns/Corefile coredns/zones/*.zone
```

Zone-файлы — не секретные, в них только публичные DNS-записи.

### CoreDNS падает на парсинге zone-файла после исправления прав

После `chmod 644` CoreDNS впервые реально читает файл и спотыкается о синтаксис. Проверь:

- **Комментарии должны начинаться с `;`, не с `#`**. Если в зоне есть строки типа `#alice IN A ...` — это парсится как запись с именем `#alice` и ломает зону.
- **`$ORIGIN`** должен заканчиваться **точкой**: `$ORIGIN lan.vpn.` (с финальной точкой), не `$ORIGIN lan.vpn`.
- **Все FQDN в записях RHS** тоже с точкой: `IN NS ns.lan.vpn.`, `IN PTR acme.lan.vpn.`. Без точки имя считается относительным к `$ORIGIN` и склеивается дважды.
- **Serial в SOA** — целое положительное число, обычно `YYYYMMDDNN`. Не плавающая точка, не строка.

### Reverse-зона не работает после копирования forward zone

В Corefile нельзя указать **один и тот же** zone-файл для прямой (`lan.vpn:53`) и обратной (`X.Y.Z.in-addr.arpa:53`) зоны — внутри лежат A-записи, а для reverse нужны PTR. Сделай отдельный файл `reverse.zone` с PTR'ами или просто удали блок reverse, если он не нужен (а в маленькой VPN он редко нужен).

Имя reverse-зоны для подсети `X.Y.Z.0/24` строится как `Z.Y.X.in-addr.arpa` (байты сети в обратном порядке). Для `10.11.12.0/24` → `12.11.10.in-addr.arpa`. Для `10.10.0.0/24` → `0.10.10.in-addr.arpa`.

### secutor-acme не стартует: `failed to unlock context: invalid password`

`acme/secrets/context_password.txt` либо не тот пароль, либо с лишним переводом строки. Проверь:
```bash
xxd acme/secrets/context_password.txt | tail
# не должно быть 0a в конце
echo -n "правильный-пароль" > acme/secrets/context_password.txt
```

### `Error: No store.enc or store.db in <path>`

Один из двух кейсов:

1. **Файла действительно нет**. Контекст `store.enc`/`store.db` должен лежать **на верхнем уровне** монтируемой папки, не во вложенной. Проверь на хосте: `ls -la /path/to/context/` — должны быть видны `store.enc` (или `store.db`) и `context.json`.

2. **Файлы есть, но папка без `x` бита**. Симптом: `ls -la` показывает `drw-rw-r--` вместо `drwx------`. Без `x` на директории `fs.existsSync` внутри ничего не находит, даже если файлы лежат. Лечение:
   ```bash
   chmod 700 /path/to/context
   chmod 600 /path/to/context/*
   ```
   Эта ситуация почти всегда — последствие `rsync --chmod=600` (он ставит 600 и на файлы, и на директории, ломая директории).

### `Error: EROFS: read-only file system, open '/tmp/secutor-acme-...db'`

`read_only: true` запрещает запись во все файловые системы контейнера, включая `/tmp`. secutor-acme при загрузке пишет расшифрованную SQLite во временный файл и сразу удаляет — нужно дать ему писать в RAM-диск. Добавь в сервис `acme`:

```yaml
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
```

И убедись, что **`SECUTOR_CONTEXT_DIR` не лежит внутри `/tmp`** — иначе bind-mount контекста перекроется tmpfs'ом и снова получишь «No store.enc». Используй путь типа `/secutor/context`.

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
- [ ] ACME отвечает на `curl -k https://acme.lan.vpn:8443/directory` с хаба. Без `-k` (с установленным root CA) — тоже должно работать.
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
