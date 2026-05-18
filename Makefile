COMPOSE ?= docker compose
PROD := -f docker-compose.yml -f docker-compose.prod.yml
HTTP := -f docker-compose.yml -f docker-compose.http.yml
ALL  := -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.http.yml

.DEFAULT_GOAL := help
.PHONY: help dev prod http down logs ps test-e2e

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

dev: down ## Start dev stack detached (frontend :80, backend :8000, postgres :5432)
	$(COMPOSE) up -d

prod: down ## Start production HTTPS stack with Caddy + Let's Encrypt (requires DOMAIN in .env)
	$(COMPOSE) $(PROD) up -d --build

http: down ## Start HTTP-only fallback stack on :80 (no TLS, no DNS required)
	$(COMPOSE) $(HTTP) up -d --build

down: ## Stop and remove containers for any running stack
	DOMAIN=_ $(COMPOSE) $(ALL) down --remove-orphans

logs: ## Tail logs from the running stack
	DOMAIN=_ $(COMPOSE) $(ALL) logs -f

ps: ## Show container status
	DOMAIN=_ $(COMPOSE) $(ALL) ps

PYTHON ?= python3

test-e2e: ## Run end-to-end Makefile/compose tests (slow, requires Docker)
	$(PYTHON) tests/e2e/test_compose_modes.py
