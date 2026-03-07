.PHONY: install install-dev test test-cov lint format typecheck docker-up docker-down clean

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/unit tests/integration -v

test-cov:
	pytest --cov=agentshield --cov-report=html

lint:
	ruff check . && black --check .

format:
	black . && ruff check --fix .

typecheck:
	mypy agentshield/

docker-up:
	docker-compose up --build -d

docker-down:
	docker-compose down -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ htmlcov/ .coverage
