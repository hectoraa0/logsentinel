.PHONY: sample analyze serve test lint docker-up docker-down

export PYTHONPATH := src
DB ?= data/logsentinel.db

sample:  ## regenerate the sample logs
	python scripts/generate_sample_logs.py data/sample

analyze:  ## analyze the sample logs
	python -m logsentinel analyze --auth data/sample/auth.log \
		--nginx data/sample/nginx_access.log --db $(DB) --year 2026

serve:  ## start the dashboard on http://127.0.0.1:8000
	python -m logsentinel serve --db $(DB)

test:
	python -m unittest discover -s tests -v

lint:
	ruff check .

docker-up:
	docker compose up -d --build
	@echo "Dashboard: http://127.0.0.1:8000"

docker-down:
	docker compose down -v
