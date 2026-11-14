# SignalHarbor

Система мониторинга сервисов, корреляции алертов и управления инцидентами. Демонстрационная реализация по техническому заданию PV-OPS-04.

**Статус: v0.3.0 — Detection & Observability. Приёмка по PV-OPS-04 ещё не завершена.**
В репозитории реализован сквозной путь ingest → durable PostgreSQL → outbox → rule worker → alert → incident → mock inbox → UI. Отдельные ограничения и невыполненные испытания описаны в [протоколе приёмки](docs/acceptance.md). Подробности v0.3.0 — в [CHANGELOG](CHANGELOG.md).

## Быстрый запуск

Требуется Docker Compose v2.

1. Скопируйте конфигурацию: `cp .env.example .env` (Windows PowerShell: `Copy-Item .env.example .env`).
2. Установите собственные `POSTGRES_PASSWORD`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (не менее 12 символов), заменив значения-заглушки.
3. Запустите: `docker compose up --build -d`.
4. Создайте администратора: `docker compose exec api python -m signalharbor.manage seed`.
5. Для демонстрационного набора: `docker compose exec api python -m signalharbor.manage demo --count 100000 --seed 42`.
6. Откройте **http://localhost:8080**. Войдите с `ADMIN_EMAIL` и `ADMIN_PASSWORD`.

Для небольшого тестового наполнения используйте `--count 1000`. Повторный запуск с тем же `--seed` продолжает с ранее записанного количества событий, не создавая дубликатов. Генератор создаёт 40 сервисов, 4 команды, 4 on-call-графика и исторические события, которые **не** рассылаются как боевые уведомления. Демонстрационные роли `engineer1@signalharbor.local`, `oncall1@signalharbor.local`, `commander1@signalharbor.local`, `observer1@signalharbor.local` (и номера 2–4) используют пароль, указанный в `ADMIN_PASSWORD`. Это только локальный тестовый контур; замените пароли перед общим доступом.

## Первый сигнал

В интерфейсе: **Управление → Ingest key**. Укажите ID окружения, сохраните полученный секрет — повторно его получить нельзя. Сервис и окружение вы найдёте в разделе «Сервисы».

Отправьте 40 ошибок:

```bash
docker compose exec api python -m signalharbor.cli \
  --url http://api:8000 --key '<your-one-time-ingest-key>' --service 1 --count 40
```

При обычных настройках rule engine через worker создаёт один firing alert и инцидент, а не 40 инцидентов. Для heartbeat:

```bash
docker compose exec api python -m signalharbor.cli \
  --url http://api:8000 --key '<your-one-time-ingest-key>' --service 1 --heartbeat
```

Вместо CLI можно использовать POST /ingest/v1/events с заголовком `X-Ingest-Key`. Максимум 500 записей в батче, обязательна `schemaVersion: 1`; событие содержит `eventId`, `serviceId`, `timestamp` (UTC/offset), `severity`, `type`. В PostgreSQL батч записывается bulk INSERT с `ON CONFLICT DO NOTHING`, без 500 отдельных SAVEPOINT. HTTP 200 возвращается **после commit**. Повтор `eventId` внутри ingest key возвращает `duplicates` и не создаёт новое событие.

## Компоненты

| Компонент | Назначение |
| --- | --- |
| FastAPI | JSON API, RBAC, события, инциденты, cookie-сессии, SSE |
| PostgreSQL 16 | События, инциденты, правила, append-only timeline, outbox |
| Worker | Применение правил, heartbeat detection, hysteresis, эскалации и retention |
| Web UI | Обзор с почасовым графиком событий, алерты, инциденты, timeline, mock inbox, replay, сервисы и администрирование |
| CLI | Тестовые события и heartbeat с backoff/jitter |
| Compose | PostgreSQL + миграционный bootstrap + API + worker |

Реализация специально не использует платные каналы SMS, Prometheus, APM или автоисправление инцидентов.

## API

- OpenAPI 3.x: [http://localhost:8080/openapi.json](http://localhost:8080/openapi.json); Swagger UI: [http://localhost:8080/docs](http://localhost:8080/docs)
- POST `/ingest/v1/events`, POST `/ingest/v1/heartbeat` — только ingest key.
- GET `/api/v1/events` — фильтры и курсор; GET `/api/v1/alerts`.
- POST `/api/v1/alert-rules`, PUT `/api/v1/alert-rules/{id}?expectedVersion=1`.
- GET `/api/v1/incidents`, POST `/{id}/ack`, POST `/{id}/resolve`, GET `/{id}/timeline`.
- GET `/stream/incidents` — SSE с `Last-Event-ID`, проверкой активной сессии и актуальной команды пользователя на каждом опросе. Сквозной тест обрыва сети пока не проводился.
- GET `/api/v1/dashboard`, GET `/api/v1/metrics`, GET `/api/v1/series` (почасовые графики).
- GET `/api/v1/ops` — только admin: размер и возраст очереди, обработанные события за час, поздние события и выборочный detection p95. В веб-интерфейсе эти показатели доступны в «Диагностике».
- POST `/api/v1/replay` — безопасная симуляция правил с управляемыми timestamp, без записи в БД и уведомлений.
- GET `/api/v1/incidents/{id}/postmortem.md` — Markdown-экспорт, POST `/{id}/severity` — история изменений severity.
- GET `/status` — публичная статусная сводка **только** для явно перечисленных `PUBLIC_STATUS_SERVICE_IDS`; по умолчанию пустая.

Создание команды, сервиса, пользователя, окружения, ключей и расписаний также доступно в API и разделе управления. Все управляющие операции требуют сессии и CSRF-token.

## Проверки

```bash
# Запуск тестов с настоящей отдельной PostgreSQL БД signalharbor_test
pip install -r requirements-dev.txt
export DATABASE_URL='postgresql+psycopg://signalharbor:test_password@localhost:5432/signalharbor_test'
pytest -q
ruff check .
node --check signalharbor/static/app.js
```

Тесты **удаляют и пересоздают** таблицы: защитная проверка не позволяет запустить их на БД без имени `signalharbor_test`. В GitHub Actions настроены PostgreSQL 16 и эти проверки.

## Что ещё не доказано

Система не считается принятой по ТЗ до прохождения всех сценариев AT-01–AT-12, включая 30-минутную нагрузку 2 000 events/min, fault injection, reconnect SSE и измерение p95. Локальный регулятор ingest рассчитан на один процесс API; многорепликовая квота требует общего storage. Миграционный runner сохраняет v1 как baseline и выполняет транзакционную миграцию v2: уникальный индекс активного инцидента и индексы worker. При обнаружении нескольких активных инцидентов одного scope миграция безопасно прерывается — записи не объединяются автоматически. Для дальнейших изменений нужны новые отдельные версии миграций. В v0.3.0 будущие события ожидают своего timestamp в outbox, а допустимые опоздавшие участвуют в расчёте event-time окон. Метрики retention агрегатов и жизненный цикл удаления metadata ещё требуют расширения.

Подробности: [архитектура](docs/architecture.md), [риски и безопасность](docs/security.md), [эксплуатация](docs/runbook.md), [протокол приёмки](docs/acceptance.md), [ADR](docs/adr/0001-data-integrity.md).

Код распространяется по лицензии MIT.
