.DEFAULT_GOAL := help
.PHONY: help up down test lint e2e seed shell mcp mcp-config

DC := docker compose
# MCP server command, with an absolute compose path so it works whatever the MCP client's cwd is.
MCP_CMD := docker compose -f $(CURDIR)/compose.yaml exec -T api python -m lawless_waf.mcp_server

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

seed: .env ## Generate two synthetic sample days for an offline trial (the 25th has the FP fixed, so the diff has something to show)
	$(DC) run --rm api sh -c 'python -m lawless_waf.sample "$$DATA_DIR/2026-06-24/merged.json" && \
		python -m lawless_waf.sample "$$DATA_DIR/2026-06-25/merged.json" --resolved'

shell: .env ## Open a shell in the API container
	$(DC) run --rm api bash

mcp: ## Register the MCP server with Claude Code at user scope (available in every folder; run `make up` first)
	-claude mcp remove --scope user lawless-waf 2>/dev/null || true
	claude mcp add --scope user lawless-waf -- $(MCP_CMD)

mcp-config: ## Print MCP config JSON for any other client (Cursor, Claude Desktop, Windsurf, …)
	@printf '%s\n' \
		'{' \
		'  "mcpServers": {' \
		'    "lawless-waf": {' \
		'      "command": "docker",' \
		'      "args": ["compose", "-f", "$(CURDIR)/compose.yaml", "exec", "-T", "api", "python", "-m", "lawless_waf.mcp_server"]' \
		'    }' \
		'  }' \
		'}'
