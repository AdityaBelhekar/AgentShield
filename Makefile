.PHONY: install install-dev test test-unit test-cov lint format typecheck docker-up docker-down clean help

help:
@echo "AgentShield — Development Commands"
@echo "==================================="
@echo "install      Install SDK"
@echo "install-dev  Install SDK + dev dependencies"
@echo "test         Run unit + integration tests"
@echo "test-unit    Run unit tests only"
@echo "test-cov     Run tests with coverage report"
@echo "lint         Check code style (ruff + black)"
@echo "format       Auto-fix code style"
@echo "typecheck    Run mypy strict type checking"
@echo "docker-up    Start Redis + backend + frontend"
@echo "docker-down  Stop all services"
@echo "clean        Remove cache and build artifacts"

install:
pip install -e .

install-dev:
pip install -e ".[dev]"

test:
pytest /scratch/tests/unit /scratch/tests/integration -v

test-unit:
pytest /scratch/tests/unit -v

test-cov:
pytest /scratch/tests/ \
  --cov=agentshield \
  --cov-report=term-missing \
  --cov-report=html:htmlcov

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
find . -type f -name "*.pyc" -delete
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true