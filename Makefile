up:
	docker compose up --build -d
seed:
	docker compose exec api python -m signalharbor.manage seed
demo:
	docker compose exec api python -m signalharbor.manage demo
test:
	pytest -q
lint:
	ruff check .
logs:
	docker compose logs -f api worker
