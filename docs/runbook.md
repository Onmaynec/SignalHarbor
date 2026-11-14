# Эксплуатация и troubleshooting

## Запуск

Заполните .env по .env.example. Затем docker compose up --build -d; docker compose exec api python -m signalharbor.manage seed. После запуска проверьте curl http://localhost:8080/health/live и /health/ready.

Сервис migrate запускает версионированные миграции (сейчас до v6) в транзакции и с PostgreSQL advisory lock. На пустой БД создаётся baseline v1; на существующей БД применяются только новые изменения. При отсутствии schema_version миграция останавливается, чтобы не угадывать структуру. Перед обновлением сделайте резервную копию; при дублях активных incident одного scope миграция v2 прервётся с ошибкой. Дубликаты нужно разбирать вручную с сохранением timeline, без принудительной потери данных.

## Логи и диагностика

docker compose ps
docker compose logs --tail=200 api worker db
docker compose exec db pg_isready -U signalharbor -d signalharbor

GET /api/v1/ops от имени admin возвращает pendingOutbox, pendingReady, pendingDeferred, oldestPendingSeconds, activeWorkers, workers (heartbeat, ошибки и накопленный объём), processedOutboxLastHour, eventsReceivedLastHour, lateEventsLastHour и detectionLagP95Ms (до 5000 переходов firing за час), а также локальные processCounters. Счётчики processCounters не переживают перезапуск API. Значение p95 из timeline — оперативная оценка, а не доказательство SLO. Эти показатели доступны в интерфейсе: «Диагностика».

Не записывайте токены в логи и issue. 401 для ingest означает отозванный/чужой ключ, 403 — чужой serviceId, 413 — превышен MAX_REQUEST_BYTES, 429 — превышен INGEST_RATE_PER_MIN (использовать Retry-After).

При высоком backlog проверьте worker и его исключения, PostgreSQL latency, размер окна правила и число группируемых labels. Если activeWorkers=0 более 20 секунд, проверьте `docker compose logs worker`, health/ready и таблицу worker_status. Настройка WORKER_BATCH_SIZE задаёт размер одной атомарной транзакции (1–500, по умолчанию 250). Увеличение размера пакета влияет на длительность блокировок и время повторной обработки после сбоя. Задания с event timestamp в пределах следующих 120 секунд могут легитимно оставаться pending до наступления времени события; отличайте их от настоящего накопления очереди.

## Event-time и проверка fingerprint

После редактирования правила проверьте `version` в `GET /api/v1/alert-rules` и `ruleVersion` у активного alert. Изменение порога/окна при неизменной группе обновляет активные alert; смена `serviceId`, `environmentId`, `kind` или `groupLabels` завершает старое поколение. При поиске исходных событий используйте `GET /api/v1/events?fingerprint=...`: запрос ограничен сохранённым временным окном и исторической конфигурацией правила. Для `count_error` возвращаются только ошибки, для `error_rate` — весь знаменатель.

Миграция v6 добавляет nullable `alerts.window_start_at` и `alerts.window_end_at`. Для существующих alert эти поля заполняются при следующей оценке; до этого API использует `fired_at` и соответствующую версию `RuleRevision` как совместимый fallback.

## Бэкап

Создать consistent dump (контейнер, пароль берётся из настроек контейнера DB):

docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U signalharbor -Fc signalharbor' > signalharbor-backup.dump

Восстановление **в отдельную остановленную тестовую БД**:

cat signalharbor-backup.dump | docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_restore -U signalharbor --clean --if-exists -d signalharbor'

Перед восстановлением остановите api/worker, сделайте бэкап текущего состояния, проверьте совместимость версии схемы. Проверяйте восстановление на отдельном стенде. Не выполняйте destructive restore на живой БД.

## Порядок проверки сбоя worker

1. Создать событие и получить HTTP 200.
2. Проверить строку ingest_events и pending outbox.
3. Перезапустить worker: docker compose restart worker.
4. Проверить alert fingerprint, incident, append-only timeline и escalations.
5. Повторить тот же eventId: новые записи появиться не должны.

## Очистка

В v0.5.0 worker **каждую минуту** запускает транзакционный lifecycle: raw events старше 30 дней, не имеющие pending outbox, сворачиваются в почасовые counts/errors/late и удаляются; агрегаты старше 180 дней удаляются; закрытые incidents удаляются через 365 дней после resolved_at вместе с зависимыми записями; открытые incidents не удаляются. За цикл обрабатывается не более 10000 старых raw events (пакеты до 1000) и 1000 закрытых incidents. При накопленном backlog очистка продолжается на следующих циклах. Ошибка в транзакции откатывает и агрегаты, и удаление raw данных. Завершённые outbox и stream events старше 30 дней также удаляются.

Проверка: GET `/api/v1/history?days=180` под ролью engineer/admin возвращает данные по дням в рамках RBAC; GET `/api/v1/ops` показывает размер очереди. Не запускайте pg_dump/restore без согласованного эксплуатационного окна. До обновления выполните бэкап и проверьте восстановление на отдельной БД.

## TOTP MFA и управление ключом

Для настройки MFA используйте Python с установленным cryptography: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Запишите результат как `MFA_ENCRYPTION_KEY` в `.env` **до** включения пользователями MFA. Не коммитьте секрет, резервируйте его отдельно от дампа БД. Ключ должен быть одинаковым во всех API-репликах. Нельзя просто сгенерировать новый ключ после потери старого: существующие MFA аккаунты перестанут входить; автоматической ротации ключей нет.

Пользователь открывает «Безопасность», вводит пароль, переносит одноразовый секрет в TOTP-приложение, подтверждает код. После подключения отображаются ровно восемь однократных recovery codes, которые нужно сохранить офлайн. При входе используйте шестизначный код или оставшийся recovery code. Отключение требует пароль и второй фактор; все сеансы прекращаются. При отсутствующем/некорректном ключе для уже включённой MFA система возвращает 503, не создавая сессию.

## Ограничение попыток входа

С v0.5.0 пароль проверяется с PostgreSQL-backed ограничением: после восьми ошибок за 15 минут аккаунт блокируется на 15 минут (429 + Retry-After). Счётчики и ключи хранятся отдельно от Users; исходные email в них не записываются. Успешный вход очищает счётчик. Возможна атака отказа в обслуживании по известному email — для внешнего доступа дополнительно необходимы TLS, IP/network rate-limit и MFA.

## Общий ingest rate-limit

В v0.6.0 `INGEST_RATE_PER_MIN` ограничивает события на каждый ingest key общим 60-секундным окном в PostgreSQL. Несколько процессов API разделяют один счётчик и используют транзакционные блокировки. При 429 клиенту следует прочитать Retry-After. Некорректный пакет откатывает резервирование квоты вместе с ingest-транзакцией. Не путать этот лимит с сетевой фильтрацией по IP и gateway-level throttling; последние не реализованы.

## Нагрузочная проверка

python scripts/load.py --url http://localhost:8080 --key KEY --service 1 --minutes 30 --rate 2000 --output load-report.json

Отчёт включает p50/p95 HTTP acknowledge и число 429/ошибок. Отдельно сохраняйте снимки GET /api/v1/ops, но не приравнивайте ограниченную выборку firing к полному detection p95; необходимо нагрузочное измерение задержки и backlog на протяжении всего 30-минутного прогона.
