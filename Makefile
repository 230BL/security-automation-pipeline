.PHONY: help install install-dev test test-unit lint type-check format up down logs clean setup-scope verify-scope sign-scope run-pipeline setup-defectdojo

PYTHON := python3
PIP := pip3
COMPOSE := docker compose -f compose/docker-compose.yml

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

install-dev: ## Install development dependencies
	$(PIP) install -r requirements-dev.txt

test: ## Run all tests
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=src --cov-report=term-missing

test-unit: ## Run unit tests only
	$(PYTHON) -m pytest tests/unit/ -v --tb=short

lint: ## Run linter
	$(PYTHON) -m ruff check src/ tests/ scripts/

format: ## Format code
	$(PYTHON) -m ruff format src/ tests/ scripts/

type-check: ## Run type checker
	$(PYTHON) -m mypy src/

up: ## Start all services
	$(COMPOSE) up -d

down: ## Stop all services
	$(COMPOSE) down

logs: ## Tail service logs
	$(COMPOSE) logs -f

clean: ## Remove generated artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/ dist/ build/ *.egg-info

setup-scope: ## Create scope directory with examples
	cp scope/scope_manifest.example.yml scope/scope_manifest.yml
	cp scope/allowlist.example.txt scope/allowlist.txt
	cp scope/maintenance_windows.example.yml scope/maintenance_windows.yml
	@echo "Edit the scope files, then run 'make sign-scope'"

sign-scope: ## Sign the scope manifest with GPG
	bash scripts/sign_scope.sh

verify-scope: ## Verify scope signature
	bash scripts/verify_scope.sh

run-pipeline: ## Run the full pipeline
	$(PYTHON) scripts/run_pipeline.py

setup-defectdojo: ## Initialize DefectDojo product structure
	$(PYTHON) scripts/setup_defectdojo.py
