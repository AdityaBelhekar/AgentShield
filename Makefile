.PHONY: install install-dev test test-cov lint format typecheck docker-up docker-down clean

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest /scratch/tests/unit /scratch/tests/integration -v

test-cov:
	pytest /scratch/tests/ --cov=agentshield \
	  --cov-report=term-missing

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
	find . -type d -name __pycache__ -exec rm -rf {} +
