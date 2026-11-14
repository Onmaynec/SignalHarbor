# Эксплуатация и troubleshooting

## Запуск

Заполните .env по .env.example. Затем docker compose up --build -d; docker compose exec api python -m signalharbor.manage seed. После запуска проверьте curl http://localhost:8080/health/live и /health/ready.

Сервис migrate запускает версионированные миграции (сейчас до v2) в транзакции и с PostgreSQL advisory lock. На пустой БД создаётся baseline v1; на существующей БД применяются только новые изменения. При отсутствии schema_version миграция останавливается, чтобы не угадывать структуру. Перед обновлением сделайте резервную копию; при дублях активных incident одного scope миграция v2 прервётся с ошибкой. Дубликаты нужно разбирать вручную с сохранением timeline, без принудительной потери данных.

## Логи и диагностика

docker compose ps
docker compose logs --tail=200 api worker db
docker compose exec db pg_isready -U signalharbor -d signalharbor

GET /api/v1/ops от имени admin возвращает pendingOutbox и локальные счётчики ingest/rejects. Счётчики не переживают перезапуск api.

Не записывайте токены в логи и issue. 401 для ingest означает отозванный/чужой ключ, 403 — чужой serviceId, 413 — превышен MAX_REQUEST_BYTES, 429 — превышен INGEST_RATE_PER_MIN (использовать Retry-After).

При высоком backlog проверьте worker и его исключения, PostgreSQL latency, размер окна правила и число группируемых labels.

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

Сейчас worker удаляет ingest events старше 30 дней **только если для них не осталось pending outbox**, завершённые outbox/stream events старше 30 дней, а также просроченные пользовательские сессии. Продление хранения metadata и агрегатов — следующий этап. Не запускайте pg_dump/restore без предварительного уточнения retention требований.

## Нагрузочная проверка

python scripts/load.py --url http://localhost:8080 --key KEY --service 1 --minutes 30 --rate 2000 --output load-report.json

Отчёт включает p50/p95 и число 429/ошибок. Он не подтверждает p95 detection до отдельной проверки задержки firing и не заменяет документирование оборудования.
