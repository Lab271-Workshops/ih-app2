.PHONY: install test lint format typecheck check

install:
	uv sync

test:
	uv run pytest tests/ -x --tb=short

test-cov:
	uv run pytest tests/ --cov=src/threat_classifier --cov-report=term-missing

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/

typecheck:
	uv run pyright src/

check: lint typecheck test
