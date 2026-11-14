# Архитектура SignalHarbor

## Данные и ответственность процессов

Client / CLI → POST ingest → проверка источника, schema, quota → транзакция PostgreSQL (Event + Outbox) → HTTP ACK.

На PostgreSQL вставка до 500 событий выполняется одним INSERT ... ON CONFLICT DO NOTHING RETURNING, затем вставляются только новые outbox rows. Для SQLite (локальная разработка) остаётся безопасная поштучная вставка через SAVEPOINT. Задержки до 1 секунды ещё не подтверждены нагрузочным испытанием.

Worker → SELECT pending outbox (PostgreSQL SKIP LOCKED) → расчёт window → unique fingerprint alert → active incident → timeline + stream event + mock notification → COMMIT. Обработка pending повторяется после падения worker; побочные эффекты должны быть идемпотентными.

Web → JSON API / cookie session → server-side entity RBAC; отдельно SSE /stream/incidents c Last-Event-ID (данные из stream_events).

## Сущности

teams, users, sessions, services, environments, ingest_keys, ingest_events, outbox, alert_rules, rule_revisions, alerts, incidents, timeline, maintenance, oncall_schedules, escalations, notifications, postmortems, stream_events.

Дедупликация: UNIQUE(key_id,event_id). Fingerprint: SHA-256 от [serviceId, environmentId, ruleId, отсортированные пары выбранных labels]. Активный инцидент ищется по service + environment + team. Это политика агрегации текущей версии (все активные alerts одного сервиса и среды попадают в один incident).

Временные значения записываются в UTC. Окно считается относительно времени worker; слишком поздние события (более 120 секунд относительно поступления) сохраняются с late=true, но не участвуют в текущих окнах. Рабочий worker переоценивает активные alerts каждые 2 секунды, чтобы восстановление происходило даже без новых событий.

## Достоверность и конкуренция

Ingest не держит собственную in-memory очередь и не ACK до COMMIT. Atomic outbox с событием запрещает потерю задачи между записью события и воркером. Два worker при PostgreSQL не захватывают один outbox row одновременно. Unique constraints защищают от повторных эффектов. Однако наилучший поддерживаемый режим текущей версии — один worker и один ingest API до завершения fault-инъекций.

ACK реализован одним условным UPDATE по состоянию open, затем append timeline в той же транзакции. Повтор от того же владельца идемпотентен, конкурирующее подтверждение возвращает HTTP 409. Эскалация оформлена как UNIQUE(incident_id,level), а уведомление как UNIQUE(incident_id,level,recipient_id).

Не гарантируется exactly-once delivery: события/запросы могут быть повторены; бизнес-эффекты должны быть повторяемыми без дублей.

## Корреляция

- count_error: число error events за rolling window строго больше порога.
- error_rate: доля error events относительно всех событий в окне, в процентах.
- heartbeat_missing: секунды после последнего heartbeat (или начала наблюдения) достигают threshold.
- recovery: threshold больше не превышен непрерывно recoverySeconds.
- cooldown: пауза между recovered и новым firing.
- maintenance: события и alert сохраняются, но mock уведомления подавляются.

## Уведомления и графики

График содержит первичного и резервного дежурного, UTC startsAt, duration rotationMinutes, timezone (IANA). Расчёт ротации идёт по абсолютному времени UTC; timezone хранится для интерпретации/отображения. L1 — текущему primary при создании incident, L2 — текущему backup при отсутствии ACK через 300 секунд. Если график не настроен, incident сохраняется, но адресного уведомления нет.

Replay по POST /api/v1/replay вычисляет переходы в памяти по контролируемым событиям и ticks. Он не создаёт Events, incidents, timeline и Notification, поэтому не порождает реального вызова дежурного.

Страница /status отдает только название и операционный статус явно разрешённых PUBLIC_STATUS_SERVICE_IDS. По умолчанию список пуст.

## Ограничения v0.1.0

- Нет изолированного queue broker и горизонтально согласованного rate-limit.
- Schema baseline создаётся через metadata.create_all, без полноценной системы upgrade/rollback.
- Нет материализованной таблицы MetricWindow, 180-дневного retention агрегатов и удаления metadata инцидентов по 365 дням.
- Записи в timeline не имеют отдельной политики запрета SQL UPDATE на уровне роли БД (append-only обеспечено API).
- Replay simulator и проверенный fault-injection пока не поставлены.
