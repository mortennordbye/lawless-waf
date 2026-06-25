.DEFAULT_GOAL := help
.PHONY: help up down test lint e2e seed shell

DC := docker compose

help: ## Show available commands
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

.env:
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example")

up: .env ## Run the app: API + web UI on http://localhost:5173 (hot reload)
	$(DC) up --build

down: ## Stop everything
	$(DC) down

test: .env ## Run the test suite
	$(DC) run --rm api pytest -q

lint: .env ## Lint the Python code (ruff)
	$(DC) run --rm api ruff check .

e2e: .env ## Offline end-to-end test against the bundled example dataset
	$(DC) run --rm api pytest -q tests/test_e2e.py

seed: .env ## Generate a synthetic sample dataset for an offline trial
	$(DC) run --rm api python -m lawless_waf.sample $$DATA_DIR/2026-06-24/merged.json

shell: .env ## Open a shell in the API container
	$(DC) run --rm api bash
