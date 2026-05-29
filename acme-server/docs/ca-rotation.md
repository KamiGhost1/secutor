# CA rotation: verify / stage / promote / rollback / reissue

Поднимает плановую (и аварийную) замену signing intermediate'а без даунтайма
ACME-эндпоинта, плюс перевыпуск всех активных leaf'ов под новый ключ.

Все операции — через [admin API](admin-api.md) поверх mTLS. В TUI они
запускаются из `Hubs → Connect → 🔄 Rotate CA`.

## Зачем

Хаб держит расшифрованный CA-приватник в RAM. Иногда его надо:

- **Проверить** — действительно ли тот ключ, который оператор положил при
  деплое; не подменили ли его supply-chain атакой / неудачным rsync /
  кривым config reload'ом.
- **Обновить** — плановая ротация intermediate'а за 6-12 месяцев до
  expiry, или экстренная замена после компрометации.
- **Прокатить по leaf'ам** — после смены intermediate'а у уже выпущенных
  leaf'ов «неправильный» issuer/AKI; пока relying parties держат старую
  цепочку в trust-store, всё работает, но в долгой перспективе надо
  переподписать.

## Проверка ключа (verify)

Доказательство владения приватником без раскрытия лишнего:

1. TUI генерит 32 случайных байта `nonce`.
2. POST `/admin/v1/ca/verify {nonce}` (требует `operator`).
3. Хаб считает `m = SHA-256("secutor-ca-verify-v1" || nonce)`, подписывает
   `m` CA-приватником (RSA-PSS для RSA, иначе обычная schema по
   алгоритму), возвращает `{alg, signature, cert_pem}`.
4. TUI верифицирует подпись против публичного ключа, который он сам
   взял из ожидаемого `.pem` (из локального контекста или с диска).

Префикс `"secutor-ca-verify-v1"` исключает риск, что подпись из verify-
протокола случайно совпадёт с TBSCertificate или CSR и будет
переиспользована атакующим. RSA-PSS отдельно отличает эту подпись от
PKCS#1 v1.5, которой подписываются сами сертификаты.

В TUI: `RemoteCaVerifyScreen` показывает зелёную/красную галку и
сравнивает fp ожидаемого cert'а с fp того, что вернул хаб.

## Двухфазное обновление: stage → promote

### Stage

`POST /admin/v1/ca/stage` (owner) принимает JSON:

```json
{
  "cert_pem":  "-----BEGIN CERTIFICATE-----\n...",
  "key_pem":   "-----BEGIN PRIVATE KEY-----\n...",  // plain PKCS#8
  "chain_pem": "-----BEGIN CERTIFICATE-----\n..."   // parents up to (incl.) root
}
```

Хаб валидирует:

1. **Key parses** — `crypto.createPrivateKey` без exception'а.
2. **Key↔cert match** — подписывается тестовый nonce приватником,
   проверяется публичным из cert'а.
3. **Same root** — последний cert в `chain_pem` должен совпадать с
   `rootCertPem` активного CA. Никакая смена trust anchor через
   обычный rotate-flow запрещена — это другой сценарий, требующий
   раздачи нового root всем клиентам.
4. **Different from active** — fingerprint cert'а ≠ fp активного.
5. **Validity ≥ 30 days** — иначе нет смысла промоутить.

Если ОК — кандидат лежит в RAM (`CaStore.staged`). Сигнинг продолжает
работать на старом ключе.

После рестарта staged исчезает — оператор должен заново вызвать stage.
Это сознательный trade-off против хранения полу-mutate'нных ключей на
диске.

### Promote

`POST /admin/v1/ca/promote` (owner):

1. Снапшотит активный материал в `previous` (для rollback).
2. `Object.assign(activeCa, stagedFields)` — атомарная in-place замена.
   Все, кто держит ссылку на `ca`-объект (routes, signer, admin
   endpoints), на следующем чтении поля видят новые данные.
3. `staged` обнуляется.
4. В `audit_log` пишется `action='ca.promote'` с `prev/new fingerprint`.

С этой секунды все новые `finalize` подписываются новым ключом.

### Rollback

`POST /admin/v1/ca/rollback` (owner) — восстанавливает `previous`, если
прошло меньше `config.admin.rollbackWindowHours` (24 по умолчанию).
После окна `previous` обнуляется автоматически (на следующей попытке
rollback'а).

Rollback — для случая «промоутили, но что-то пошло не так и leaves под
новый ключ ещё не валидируются relying parties». Не для «откатим
скомпрометированный новый ключ» — для этого нужен новый stage + promote
старого материала.

## Reissue worker

После promote — фоновый процесс перевыпускает leaf'ы под новый ключ.

`POST /admin/v1/jobs/reissue` (owner) body:

```json
{
  "scope": "all-active",                  // | "by-account" | "by-identifier-pattern"
  "accountIds": ["..."],                  // для by-account
  "identifierPattern": "*.lan.vpn",       // для by-identifier-pattern
  "ratePerSec": 10                        // default 10, max 200
}
```

Что делает worker:

1. Снимает SPKI из старого cert'а — это публичный ключ клиента, остаётся
   прежним.
2. Снимает SANs / CN / validity из старого cert'а.
3. Зовёт `issueLeaf` с этими данными + текущим активным CA-ключом.
4. Обновляет `certificates.pem` + `serial_hex` той же row id.

В таблицах `reissue_jobs` + `reissue_job_items` отслеживается прогресс.
Worker переживает рестарт — на следующем тике добирает оставшиеся
`pending` items.

`POST /admin/v1/jobs/:id/cancel` (owner) — мягкий cancel: помечает job
`cancelled`, текущий running item доделывается, дальше остановка.

В TUI: `JobProgressScreen` поллит `GET /jobs/:id` раз в секунду, рисует
полосу `done/failed/pending`, `C` отменяет.

Клиенты, у которых лежит старый файл сертификата, увидят свежий
сертификат при следующем `GET /cert/:id` (cert-manager делает это перед
renew). Для ARI-aware клиентов `GET /renewalInfo/:id` отдаёт окно,
которое после reissue фактически становится «renew now-ish».

## Типичные сценарии

### Плановая ротация intermediate

1. На admin-машине: создайте новый intermediate под тем же root.
2. Соберите его в `.skb` (cert + key + parent root), либо положите в
   локальный контекст с приватником.
3. В TUI: `Hubs → Connect → 🔄 Rotate CA → Stage new CA material`.
4. Выберите источник, подтвердите.
5. Когда staging показывает зелёный кандидат — `Promote`.
6. (Опционально) `Re-sign all active leaves` — фоновая джоба.

### Компрометация intermediate

1. Stage чистый новый intermediate (под тем же root).
2. Promote.
3. Запустите CRL job на старом — `GET /crl.pem` теперь включает
   старый intermediate как revoked... (на самом деле, для отзыва
   intermediate'а нужен root — это вне scope rotate-flow; см.
   ca-lifecycle.md).
4. Запустите reissue, чтобы новые leaf-подписи разошлись клиентам.

### Тест без последствий

1. Stage кандидат.
2. Verify через `POST /admin/v1/ca/verify` — увидите, что подпись всё
   ещё валидирует против СТАРОГО cert_pem (потому что promote ещё не
   было).
3. `DELETE /admin/v1/ca/staged` — кандидат отменяется, ничего не
   тронуто.
