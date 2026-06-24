.PHONY: help install test lint format check cov clean docker-up docker-down status

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install package + dev dependencies
	pip install -e ".[dev]"

test:  ## Run the test suite
	pytest tests/ -v

cov:  ## Run tests with coverage report
	pytest tests/ --cov=tip --cov-report=term-missing

lint:  ## Lint with ruff
	ruff check tip/ tests/

format:  ## Auto-format with ruff
	ruff format tip/ tests/
	ruff check --fix tip/ tests/

check:  ## Run the full CI gate locally (lint + format-check + tests)
	ruff check tip/ tests/
	ruff format --check tip/ tests/
	pytest tests/ -q

docker-up:  ## Start MISP stack (core services)
	docker compose -f docker/docker-compose.yml up -d misp misp-db misp-redis

docker-up-elastic:  ## Start MISP + Elastic + Kibana
	docker compose -f docker/docker-compose.yml --profile elastic up -d

docker-down:  ## Stop all containers
	docker compose -f docker/docker-compose.yml down

status:  ## Health-check all services
	tip status --retry 5

clean:  ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
