# Архитектура SignalHarbor

## Данные и ответственность процессов

Client / CLI → POST ingest → проверка источника, schema, quota → транзакция PostgreSQL (Event + Outbox) → HTTP ACK.

На PostgreSQL вставка до 500 событий выполняется одним INSERT ... ON CONFLICT DO NOTHING RETURNING, затем вставляются только новые outbox rows. Для SQLite (локальная разработка) остаётся безопасная поштучная вставка через SAVEPOINT. Задержки до 1 секунды ещё не подтверждены нагрузочным испытанием.

Worker → SELECT только готовые по timestamp pending outbox (PostgreSQL SKIP LOCKED) → группировка по rule/service/environment/selected labels → единичная оценка окна для каждой группы → advisory lock fingerprint → unique fingerprint alert → active incident → timeline + stream event + mock notification → COMMIT. Обработка pending повторяется после падения worker; побочные эффекты должны быть идемпотентными.

Web → JSON API / cookie session → server-side entity RBAC; отдельно SSE /stream/incidents c Last-Event-ID (данные из stream_events).

## Сущности

teams, users, sessions, services, environments, ingest_keys, ingest_events, outbox, alert_rules, rule_revisions, alerts, incidents, timeline, maintenance, oncall_schedules, escalations, notifications, postmortems, stream_events.

Дедупликация: UNIQUE(key_id,event_id). Fingerprint: SHA-256 от [serviceId, environmentId, ruleId, отсортированные пары выбранных labels]. Активный инцидент ищется по service + environment + team. В PostgreSQL используется pg_advisory_xact_lock по environment_id до поиска первого инцидента, а частичный уникальный индекс не допускает два незакрытых incident одного scope. Это политика агрегации текущей версии (все активные alerts одного сервиса и среды попадают в один incident).

Временные значения записываются в UTC. Бounded out-of-order события (не старше 120 секунд относительно получения) при evaluation используют event-time watermark выбранной группы: максимальный timestamp её уже записанных допустимых событий. Это позволяет учесть 90-секундную задержку даже в 30-секундном окне. Для активных alert и recovery периодическая проверка каждые 2 секунды выполняется по времени worker. Слишком поздние события (>120 секунд) сохраняются с late=true и не запускают rule-engine. События с допустимым будущим timestamp остаются pending в durable outbox до наступления timestamp.

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

## Наблюдаемость worker

Миграция v3 добавляет таблицу worker_status. Каждый worker пишет heartbeat примерно раз в 5 секунд, общее число обработанных задач и число пойманных ошибок. API считает worker активным при heartbeat не старше 20 секунд. GET /api/v1/ops (admin) разделяет ready backlog и future-deferred backlog; информация отображается во вкладке «Диагностика». Worker использует WORKER_BATCH_SIZE (1–500, по умолчанию 250). Эти метрики не заменяют измерение SLO в долгом нагрузочном тесте.

## Уведомления и графики

График содержит первичного и резервного дежурного, UTC startsAt, duration rotationMinutes, timezone (IANA). Расчёт ротации идёт по абсолютному времени UTC; timezone хранится для интерпретации/отображения. L1 — текущему primary при создании incident, L2 — текущему backup при отсутствии ACK через 300 секунд. Если график не настроен, incident сохраняется, но адресного уведомления нет.

Первые срабатывания alert записывают в timeline поле detectionLagMs — задержку от received_at исходного события до перехода firing. GET /api/v1/ops предоставляет размер и возраст pending outbox, почасовые counters, p95 по ограниченной выборке свежих alert_fired (не является подтверждённым SLO). SSE повторно проверяет текущие права и сессию при каждой итерации чтения; завершённые/отозванные сессии прекращают поток.

Replay по POST /api/v1/replay вычисляет переходы в памяти по контролируемым событиям и ticks. Он не создаёт Events, incidents, timeline и Notification, поэтому не порождает реального вызова дежурного.

Страница /status отдает только название и операционный статус явно разрешённых PUBLIC_STATUS_SERVICE_IDS. По умолчанию список пуст.

## Ограничения v0.4.0

- Нет изолированного queue broker и горизонтально согласованного rate-limit.
- Версия схемы v3 обновляется транзакционно через migrations.py (новая таблица worker_status); дальнейшие изменения должны оформляться отдельными миграциями.
- Нет материализованной таблицы MetricWindow, 180-дневного retention агрегатов и удаления metadata инцидентов по 365 дням.
- Записи в timeline не имеют отдельной политики запрета SQL UPDATE на уровне роли БД (append-only обеспечено API).
- Replay simulator доступен, но проверенный fault-injection с kill/restart контейнеров пока не проведён.
