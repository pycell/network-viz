.DEFAULT_GOAL := help

UV_CACHE_DIR ?= .uv-cache
UV ?= UV_CACHE_DIR=$(UV_CACHE_DIR) python3 -m uv
PYTHON ?= $(UV) run
FRONTEND_DIR := frontend
COMPOSE ?= docker compose
XML ?= tests/pf_config.xml

.PHONY: help install install-backend install-frontend dev-backend dev-backend-reload dev-frontend parse-pfsense analyze-pfsense test lint format typecheck docker-build docker-up docker-down docker-logs db-shell clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "%-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: install-backend install-frontend ## Install backend and frontend dependencies

install-backend: ## Install Python dependencies with uv
	$(UV) sync

install-frontend: ## Install frontend dependencies
	cd $(FRONTEND_DIR) && npm install

dev-backend: ## Run FastAPI backend locally
	$(PYTHON) uvicorn network_viz.api.main:app --host 127.0.0.1 --port 8000

dev-backend-reload: ## Run FastAPI backend locally with reload
	$(PYTHON) uvicorn network_viz.api.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir backend

dev-frontend: ## Run React frontend locally
	cd $(FRONTEND_DIR) && npm run dev

parse-pfsense: ## Parse pfSense XML. Usage: make parse-pfsense XML=tests/pf_config.xml
	@test -n "$(XML)" || (echo "Usage: make parse-pfsense XML=tests/pf_config.xml" && exit 2)
	$(PYTHON) network-viz parse-pfsense $(XML)

analyze-pfsense: ## Parse pfSense XML and generate risk findings. Usage: make analyze-pfsense XML=tests/pf_config.xml
	@test -n "$(XML)" || (echo "Usage: make analyze-pfsense XML=tests/pf_config.xml" && exit 2)
	$(PYTHON) network-viz analyze-pfsense $(XML)

test: ## Run backend tests
	$(PYTHON) pytest

lint: ## Run backend and frontend linters
	$(PYTHON) ruff check backend tests
	cd $(FRONTEND_DIR) && npm run lint

format: ## Format backend code
	$(PYTHON) ruff format backend tests
	$(PYTHON) ruff check --fix backend tests

typecheck: ## Run Python type checks
	$(PYTHON) mypy

docker-build: ## Build application Docker image
	$(COMPOSE) build

docker-up: ## Start application and PostgreSQL
	$(COMPOSE) up --build

docker-down: ## Stop containers
	$(COMPOSE) down

docker-logs: ## Follow application logs
	$(COMPOSE) logs -f app

db-shell: ## Open psql shell in PostgreSQL container
	$(COMPOSE) exec postgres psql -U network_viz -d network_viz

clean: ## Remove local caches and build outputs
	rm -rf .pytest_cache .ruff_cache .mypy_cache frontend/dist frontend/.vite frontend/*.tsbuildinfo frontend/vite.config.js
