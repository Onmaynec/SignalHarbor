# Архитектура SignalHarbor

## Данные и ответственность процессов

Client / CLI → POST ingest → проверка источника, schema, quota → транзакция PostgreSQL (Event + Outbox) → HTTP ACK.

На PostgreSQL вставка до 500 событий выполняется одним INSERT ... ON CONFLICT DO NOTHING RETURNING, затем вставляются только новые outbox rows. Для SQLite (локальная разработка) остаётся безопасная поштучная вставка через SAVEPOINT. Задержки до 1 секунды ещё не подтверждены нагрузочным испытанием.

Worker → SELECT только готовые по timestamp pending outbox (PostgreSQL SKIP LOCKED) → группировка по rule/service/environment/selected labels → единичная оценка окна для каждой группы → advisory lock fingerprint → unique fingerprint alert → active incident → timeline + stream event + mock notification → COMMIT. Обработка pending повторяется после падения worker; побочные эффекты должны быть идемпотентными.

Web → JSON API / cookie session → server-side entity RBAC; отдельно SSE /stream/incidents c Last-Event-ID (данные из stream_events).

## Сущности

teams, users, sessions, services, environments, ingest_keys, ingest_events, outbox, alert_rules, rule_revisions, alerts, incidents, timeline, maintenance, oncall_schedules, escalations, notifications, postmortems, stream_events.

Дедупликация: UNIQUE(key_id,event_id). Fingerprint: SHA-256 от [serviceId, environmentId, ruleId, отсортированные пары выбранных labels]. Активный инцидент ищется по service + environment + team. В PostgreSQL используется pg_advisory_xact_lock по environment_id до поиска первого инцидента, а частичный уникальный индекс не допускает два незакрытых incident одного scope. Это политика агрегации текущей версии (все активные alerts одного сервиса и среды попадают в один incident).

Временные значения записываются в UTC. Bounded out-of-order события (не старше 120 секунд относительно получения) при evaluation используют event-time watermark выбранной группы service/environment/rule/selected labels: максимальный timestamp уже записанного допустимого события. Watermark не зависит от того, пришёл ли старый пакет до нового или после него; окно строится относительно watermark, а не времени получения. Это позволяет учесть 90-секундную задержку даже в 30-секундном окне. Отсутствующая выбранная label нормализуется в пустую строку одинаково в fingerprint, watermark и SQL-фильтре окна. Слишком поздние события (>120 секунд) сохраняются с late=true и не запускают rule-engine. События с допустимым будущим timestamp остаются pending в durable outbox до наступления timestamp. Для active alert и recovery периодическая проверка каждые 2 секунды выполняется по времени worker.

## Достоверность и конкуренция

Ingest не держит собственную in-memory очередь и не ACK до COMMIT. Atomic outbox с событием запрещает потерю задачи между записью события и воркером. Два worker при PostgreSQL не захватывают один outbox row одновременно. При ошибке внутри пакетной транзакции отметки обработанных outbox tasks и новые инциденты откатываются вместе; повторный запуск заново выполняет обработку. Unique constraints защищают от повторных эффектов. Однако наилучший поддерживаемый режим текущей версии — один worker и один ingest API до завершения fault-инъекций.

ACK реализован одним условным UPDATE по состоянию open, затем append timeline в той же транзакции. Повтор от того же владельца идемпотентен, конкурирующее подтверждение возвращает HTTP 409. Эскалация оформлена как UNIQUE(incident_id,level), а уведомление как UNIQUE(incident_id,level,recipient_id).

Не гарантируется exactly-once delivery: события/запросы могут быть повторены; бизнес-эффекты должны быть повторяемыми без дублей.

## Корреляция

- count_error: число error events за rolling window строго больше порога.
- error_rate: доля error events относительно всех событий в окне, в процентах.
- heartbeat_missing: секунды после последнего heartbeat (или начала наблюдения) достигают threshold.
- recovery: threshold больше не превышен непрерывно recoverySeconds.
- cooldown: пауза между recovered и новым firing.
- maintenance: события и alert сохраняются, но mock уведомления подавляются.

## Event-time, поколения alert и fingerprint query

Для каждой оценки alert сохраняются `window_start_at` и `window_end_at`: фактические границы event-time окна, использованного для вычисления значения. GET `/api/v1/events?fingerprint=...` применяет scope service/environment, сохранённые label values, точные границы окна и семантику rule из версии `RuleRevision`: `count_error` возвращает только error events (`kind=error` или `severity=error`), `error_rate` — все события знаменателя, `heartbeat_missing` — heartbeat до конца интервала. Это не смешивает одинаковые service/environment/labels у правил разных типов или окон. Для отсутствующих labels применяется `COALESCE(..., '')`, поэтому SQL-группировка совпадает с построением fingerprint.

Изменение порога, окна, cooldown, recovery или severity при неизменных service/environment/kind/groupLabels повышает `rule_version` и сразу переоценивает активные alert; смена scope, kind, selected labels или выключение правила завершает прежнее поколение alert с timeline-событием `alert_reconfigured`. Старый alert сохраняет свою версию и fingerprint. При первом редактировании legacy-правила перед новой ревизией фиксируется его прежняя конфигурация, если записи истории ещё нет.

Hysteresis требует непрерывного периода ниже порога. Если событие во время cooldown снова превышает порог, alert не открывается немедленно; после истечения cooldown периодический evaluator проверяет recovered alert текущей версии по признаку `last_seen_at > recovered_at`. Если условие всё ещё выполняется, создаётся `refired`; recovered alert без нового firing-сигнала не опрашиваются постоянно. Старые поколения, закрытые изменением grouping/scope, не переоткрываются periodic scan.

Значения: для `count_error` `value` — число ошибок и `count` — число ошибок; для `error_rate` `value` — процент ошибок, `count` — число error events в окне; для `heartbeat_missing` `value` — секунды после последнего heartbeat, `count=1`. `window_start_at/window_end_at` фиксируют фактическое окно, а `fired_at` остаётся временем перехода alert в firing.

## Политика хранения и защита входа

Миграция v4 создаёт `metric_hours` и `login_attempts`. Worker раз в минуту исполняет транзакционную очистку: до 10000 raw events за вызов (пакетами до 1000) старше 30 дней без ожидающего outbox, одновременно добавляя counts/errors/late по часовым UTC-бакетам в агрегаты. Агрегаты старше 180 дней удаляются, а закрытые incidents старше 365 дней после `resolved_at` — вместе с зависимыми alert, timeline, notifications, escalations, postmortems и stream events. Открытые incidents никогда не удаляются возрастной политикой. `/api/v1/history` объединяет архивные агрегаты и текущие сырые события без двойного счёта и учитывает RBAC.

Login throttling: в PostgreSQL по хешу нормализованного email хранятся попытки; транзакционная advisory lock исключает гонку первого вставления. Восемь неуспешных паролей за 15 минут приводят к временному ограничению на 15 минут. Неизвестные пользователи проверяются на фиктивном хеше, чтобы уменьшить тайминговую утечку. Это не замена MFA, сетевому throttling и защите от атак блокировки чужих аккаунтов.

## Аутентификация и общий ingest-limit

TOTP MFA (RFC 6238) необязательна: включается пользователем с повторной проверкой пароля, хранит Fernet-encrypted seed и одноразовые хеши восстановительных кодов. При входе сначала проверяется пароль, затем заблокированная строка credential проверяет новый временной шаг TOTP либо погашает recovery-code; только после этого атомарно выдаётся сессия. Сеансы остальных устройств отзываются при включении MFA; при отключении — все сеансы. Секрет шифрования передаётся через MFA_ENCRYPTION_KEY и должен быть одинаковым на репликах API; отсутствие ключа при включённой MFA блокирует логин.

В PostgreSQL таблица ingest_quotas содержит fixed 60-second window per ingest key. Под advisory transaction lock каждая API-реплика резервирует единицы события, затем одним commit вместе с Event+Outbox фиксирует квоту. Неверный пакет делает rollback квоты, клиент получает 429 и Retry-After при превышении лимита. SQLite остаётся dev-only fallback с локальным лимитером.

## Наблюдаемость worker

Миграция v3 добавляет таблицу worker_status. Каждый worker пишет heartbeat примерно раз в 5 секунд, общее число обработанных задач и число пойманных ошибок. API считает worker активным при heartbeat не старше 20 секунд. GET /api/v1/ops (admin) разделяет ready backlog и future-deferred backlog; информация отображается во вкладке «Диагностика». Worker использует WORKER_BATCH_SIZE (1–500, по умолчанию 250). Эти метрики не заменяют измерение SLO в долгом нагрузочном тесте.

## Уведомления и графики

График содержит первичного и резервного дежурного, UTC startsAt, duration rotationMinutes, timezone (IANA). Расчёт ротации идёт по абсолютному времени UTC; timezone хранится для интерпретации/отображения. L1 — текущему primary при создании incident, L2 — текущему backup при отсутствии ACK через 300 секунд. Если график не настроен, incident сохраняется, но адресного уведомления нет.

Первые срабатывания alert записывают в timeline поле detectionLagMs — задержку от received_at исходного события до перехода firing. GET /api/v1/ops предоставляет размер и возраст pending outbox, почасовые counters, p95 по ограниченной выборке свежих alert_fired (не является подтверждённым SLO). SSE повторно проверяет текущие права и сессию при каждой итерации чтения; завершённые/отозванные сессии прекращают поток.

Replay по POST /api/v1/replay вычисляет переходы в памяти по контролируемым событиям и ticks. Он не создаёт Events, incidents, timeline и Notification, поэтому не порождает реального вызова дежурного.

Страница /status отдает только название и операционный статус явно разрешённых PUBLIC_STATUS_SERVICE_IDS. По умолчанию список пуст.

## Ограничения v0.7.0

- Нет отдельного queue broker; ingest quota синхронизируется через PostgreSQL per key, но IP/network throttling на reverse proxy пока не реализован.
- Версия схемы v5 добавляет `mfa_credentials`, `mfa_enrollments` и `ingest_quotas`; v6 добавляет `alerts.window_start_at` и `alerts.window_end_at` для сохранения границ event-time окна. Последующие изменения должны оформляться отдельными миграциями.
- Для аналитики за пределами raw retention доступны только почасовые агрегаты per team/service/environment, без отдельных labels и payload. Накопительная свёртка транзакционная; нагрузочный прогон массовой архивной очистки ещё не подтверждён.
- Записи в timeline не имеют отдельной политики запрета SQL UPDATE на уровне роли БД (append-only обеспечено API).
- Replay simulator доступен, но проверенный fault-injection с kill/restart контейнеров пока не проведён.
