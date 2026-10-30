# ScopeLens — M2 backend and lab verification

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE_DEV := docker compose --env-file .env -f deploy/docker-compose.dev.yml
COMPOSE_LABS := docker compose -f labs/docker-compose.yml
UV := uv run

.PHONY: help install init-env test-proxy proxy-image run down down-hard db-up db-down test test-unit test-all \
        lint fmt check-registry manifest proxy-image test-proxy verify-proxy-live hash-password migrate seed-operator \
        labs-up labs-up-juice labs-down labs-seed labs-reset labs-verify labs-readiness \
        frontend frontend-build pin clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Setup -------------------------------------------------------------------------

install: init-env ## Create the venv, install pinned Python and frontend deps, write .env
	uv sync --frozen
	pnpm --dir frontend install --frozen-lockfile
	@echo
	@echo "Installed. Next: \`make run\` (dev stack) and \`make frontend\` (dashboard)."

init-env: ## Create .env from .env.example with generated secrets (never overwrites)
	@if [ -f .env ]; then \
		echo ".env already exists — leaving it untouched."; \
	else \
		uv run --no-project python scripts/bootstrap_env.py; \
	fi

pin: ## Re-lock dependencies (edit version ranges in pyproject.toml first)
	uv lock
	uv sync --frozen

# --- Dev stack ---------------------------------------------------------------------

run: run-m4 ## Start all Phase 1 backend scanning lanes and owned labs

# The proxy joins the lab network so a scan can reach the fixtures through the broker.
# Compose fails with a bare "network not found", which is unhelpful at 1am.
check-lab-network: ## Fail with instructions if the labs stack has not been started
	@if ! docker network inspect scopelens_labs_net >/dev/null 2>&1; then \
		echo "error: the lab network 'scopelens_labs_net' does not exist."; \
		echo "       The dev stack joins it so scans can reach the fixtures through the"; \
		echo "       proxy. Start the labs first:"; \
		echo; \
		echo "         make labs-up"; \
		echo "         make run"; \
		exit 1; \
	fi

worker-image: ## Build the isolated worker image the supervisor launches
	docker build -f workers/tool-worker.Dockerfile -t scopelens/tool-worker:dev .

down: ## Stop the dev stack (keeps the database volume)
	$(COMPOSE_DEV) down

down-hard: ## Stop the dev stack AND delete the database volume
	@echo "This destroys all local scan metadata. Labs are untouched."
	$(COMPOSE_DEV) down -v

db-up: ## Start only PostgreSQL and wait until it is healthy
	$(COMPOSE_DEV) up -d --wait postgres

db-down: ## Stop only PostgreSQL
	$(COMPOSE_DEV) stop postgres

migrate: ## Apply database migrations to head
	$(UV) scopelens migrate

seed-operator: ## Create or refresh the single operator account from .env
	$(UV) scopelens seed-operator

reconcile: ## Reconcile orphans, stale leases and lost outcomes
	$(UV) scopelens reconcile

dispatch-once: ## Drain the outbox once and report what was enqueued
	$(UV) scopelens dispatch --once

hash-password: ## Generate a bcrypt hash for SCOPELENS_OPERATOR_PASSWORD_HASH
	@$(UV) scopelens hash-password

frontend: ## Run the dashboard dev server (proxies /api to the API)
	SCOPELENS_LOCAL_WORKSPACE=1 pnpm --dir frontend dev

frontend-build: ## Typecheck and build the dashboard
	pnpm --dir frontend build

# --- Quality -----------------------------------------------------------------------

test: ## Run the test suite (database tests skip if PostgreSQL is down)
	$(UV) pytest

test-unit: ## Run only tests that need no database
	$(UV) pytest -m "not db"

test-all: db-up ## Start PostgreSQL, then run the entire suite
	$(UV) pytest
	$(MAKE) --no-print-directory test-proxy

lint: ## Ruff (backend, evaluation, tests) plus a dashboard typecheck
	$(UV) ruff check backend tests evaluation scripts
	$(UV) ruff format --check backend tests evaluation scripts
	pnpm --dir frontend typecheck

fmt: ## Auto-format and auto-fix
	$(UV) ruff format backend tests evaluation
	$(UV) ruff check --fix backend tests evaluation

test-proxy: proxy-image ## Prove the CONNECT bypass is closed and raw TCP never reaches a target
	@docker run --rm --network none \
		-v "$$PWD/backend/scopelens/broker/mitm_addon.py:/addons/scope_enforcer.py:ro" \
		-v "$$PWD/tests/containment:/tests:ro" \
		--entrypoint python3 scopelens/proxy:dev /tests/proxy_signed_https.py
	@docker run --rm --network none \
		-v "$$PWD/backend/scopelens/broker/mitm_addon.py:/addons/scope_enforcer.py:ro" \
		-v "$$PWD/tests/containment:/tests:ro" \
		--entrypoint python3 scopelens/proxy:dev /tests/proxy_control_responsiveness.py
	@docker run --rm \
		-v "$$PWD/backend/scopelens/broker/mitm_addon.py:/addons/scope_enforcer.py:ro" \
		-v "$$PWD/tests/containment/proxy_bypass.py:/probe.py:ro" \
		--entrypoint python3 scopelens/proxy:dev /probe.py
	@docker run --rm --network none \
		-v "$$PWD/backend/scopelens/broker/mitm_addon.py:/addons/scope_enforcer.py:ro" \
		-v "$$PWD/tests/containment:/tests:ro" \
		--entrypoint python3 scopelens/proxy:dev /tests/proxy_keepalive.py
	@docker run --rm --network none \
		-v "$$PWD/backend/scopelens/broker/mitm_addon.py:/addons/scope_enforcer.py:ro" \
		-v "$$PWD/tests/containment:/tests:ro" \
		--entrypoint python3 scopelens/proxy:dev /tests/proxy_queue.py
	@docker run --rm --network none \
		-v "$$PWD/backend/scopelens/broker/mitm_addon.py:/addons/scope_enforcer.py:ro" \
		-v "$$PWD/tests/containment:/tests:ro" \
		--entrypoint python3 scopelens/proxy:dev /tests/callback_capture.py

verify-proxy-live: ## Prove a worker's token cannot tunnel to Redis or PostgreSQL (needs `make run`)
	@docker cp tests/containment/live_proxy_probe.py scopelens-dev-supervisor-1:/tmp/live_proxy_probe.py >/dev/null
	@docker compose --env-file .env -f deploy/docker-compose.dev.yml exec -T supervisor \
		python /tmp/live_proxy_probe.py

proxy-image: ## Build the forward proxy image
	docker build -f deploy/proxy.Dockerfile -t scopelens/proxy:dev .

check-registry: ## Validate every check-registry entry
	$(UV) scopelens check-registry

manifest: ## Regenerate the release manifest
	$(UV) scopelens manifest

# --- Labs --------------------------------------------------------------------------

labs-up: labs-seed ## Start the good/bad nginx fixture pair
	$(COMPOSE_LABS) up -d --wait
	@sh labs/scripts/readiness.sh

labs-up-juice: labs-seed ## Start the fixtures plus OWASP Juice Shop (opt-in, heavier)
	$(COMPOSE_LABS) --profile juice-shop up -d --wait

.PHONY: labs-up-discovery verify-discovery
labs-up-discovery: ## Start only the isolated discovery development pair
	$(COMPOSE_LABS) --profile discovery up -d --wait labs-discovery-a labs-discovery-b

verify-discovery: ## Discover then assess the owned discovery pair through the running backend
	$(UV) python -m scripts.verify_discovery_lab

labs-seed: ## Generate the fixture certificate (idempotent)
	@sh labs/scripts/seed.sh

labs-down: ## Stop the lab stack and remove its volumes
	$(COMPOSE_LABS) --profile juice-shop down -v --remove-orphans

labs-reset: ## Reset fixtures to a known state (required before a measured run)
	@sh labs/scripts/reset.sh

labs-verify: ## Assert the fixtures really differ as designed
	@sh labs/scripts/verify.sh

labs-readiness: ## Wait for the fixtures to be ready
	@sh labs/scripts/readiness.sh

clean: ## Remove caches and build output
	rm -rf .pytest_cache .ruff_cache frontend/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# --- M3 browser and mature tool path ------------------------------------------------
.PHONY: m3-images run-m3 verify-m3
m3-images: ## Download hash-verified tools and build both isolated worker images
	$(UV) python scripts/fetch_m3_tools.py
	docker build -f workers/kali-tool.Dockerfile -t scopelens/kali-tool:dev .
	docker build -f workers/browser-worker.Dockerfile -t scopelens/browser-worker:dev .

run-m3: m3-images labs-up ## Start M3 with immutable worker image IDs
	SCOPELENS_KALI_WORKER_IMAGE="$$(docker image inspect scopelens/kali-tool:dev --format '{{.Id}}')" \
	SCOPELENS_BROWSER_WORKER_IMAGE="$$(docker image inspect scopelens/browser-worker:dev --format '{{.Id}}')" \
	$(COMPOSE_DEV) -f deploy/docker-compose.m3.yml up -d --build --wait

verify-m3: ## Run the real M3 lab gate (requires make run-m3)
	$(UV) python scripts/verify_m3_lab.py

.PHONY: verify-expanded-browser
verify-expanded-browser: ## Exercise disposable browser workflows through the deployed VM and reports
	$(UV) python scripts/verify_expanded_browser_lab.py

.PHONY: verify-authenticated-inputs
verify-authenticated-inputs: ## Verify encrypted credentials and authenticated lab findings through exports
	$(UV) python scripts/verify_authenticated_inputs_lab.py

.PHONY: verify-authenticated-browser
verify-authenticated-browser: ## Verify authenticated browser context proofs and redacted lab reports
	PYTHONPATH=.:backend $(UV) python scripts/verify_authenticated_browser_lab.py

run-m4: worker-image m3-images labs-up ## Start the adaptive backend and every reviewed scanning lane
	SCOPELENS_KALI_WORKER_IMAGE=$$(docker image inspect scopelens/kali-tool:dev --format '{{.Id}}') \
	SCOPELENS_BROWSER_WORKER_IMAGE=$$(docker image inspect scopelens/browser-worker:dev --format '{{.Id}}') \
	SCOPELENS_TOOL_WORKER_IMAGE=$$(docker image inspect scopelens/tool-worker:dev --format '{{.Id}}') \
	$(COMPOSE_DEV) -f deploy/docker-compose.m4.yml up -d --build --wait

sandbox-up: ## Start the dedicated local-analysis VM (Lima on macOS)
	limactl start --name=scopelens-sandbox --tty=false deploy/sandbox/lima.yaml
	limactl shell scopelens-sandbox -- sudo mkdir -p /opt/scopelens
	limactl copy deploy/sandbox/guest_runner.py scopelens-sandbox:/tmp/scopelens_guest_runner.py
	limactl shell scopelens-sandbox -- sudo install -m 0555 /tmp/scopelens_guest_runner.py /opt/scopelens/guest_runner.py

sandbox-gateway: ## Serve the authenticated local VM gateway
	uv run uvicorn scopelens.execution.sandbox:app --host 127.0.0.1 --port 8097

verify-m4: ## Run paired active controls and adaptive follow-ups on owned labs
	uv run python scripts/verify_m4_lab.py

verify-sandbox: ## Measure dedicated-VM containment and limits
	uv run python scripts/verify_sandbox.py

retention-plan: ## List terminal-scan evidence beyond retention, without deleting it
	@docker cp scripts/retention.py scopelens-dev-supervisor-1:/tmp/scopelens_retention.py
	docker exec scopelens-dev-supervisor-1 python /tmp/scopelens_retention.py

freeze-release: ## Freeze built immutable image IDs and source fingerprint
	uv run python -m scripts.freeze_release

run-release: ## Start frozen backend images without source mounts (after freeze-release)
	docker compose --env-file .env --env-file runs/release/images.env -f deploy/docker-compose.dev.yml -f deploy/docker-compose.m4.yml -f deploy/docker-compose.release.yml up -d --no-build --wait

worker-vm-up: ## Create/start the dedicated reviewed-scanner VM (Apple Silicon)
	limactl start --name=scopelens-workers --tty=false deploy/worker_vm/lima.yaml

worker-vm-provision: ## Install mutual TLS, frozen worker images, fixed proxy relay and firewall
	uv run python scripts/provision_worker_vm.py

verify-worker-vm: ## Measure the dedicated worker VM boundary and cancellation
	uv run python scripts/verify_worker_vm.py

run-worker-vm: verify-worker-vm ## Run the frozen backend with workers on the dedicated VM
	docker compose --env-file .env --env-file runs/release/images.env -f deploy/docker-compose.dev.yml -f deploy/docker-compose.m4.yml -f deploy/docker-compose.release.yml -f deploy/docker-compose.worker-vm.yml up -d --no-build --wait

verify-sandbox-rpc: ## Measure VM lab-only broker RPC and revocation
	uv run python scripts/verify_sandbox_rpc.py

install-backend: init-env ## Install only backend dependencies
	uv sync --frozen

qualify-models: ## Call configured approved providers with synthetic prompts (may incur configured cost)
	uv run python scripts/qualify_models.py

retention-apply: ## Delete expired evidence bytes in the running store; keep metadata
	@docker cp scripts/retention.py scopelens-dev-supervisor-1:/tmp/scopelens_retention.py
	docker exec scopelens-dev-supervisor-1 python /tmp/scopelens_retention.py --apply

validate-active: ## Run independently health-checked active validation fixtures (requires run-m4)
	uv run python -m evaluation.validate_active --output runs/validation-$$(date -u +%Y%m%dT%H%M%SZ)

.PHONY: verify-callbacks
verify-callbacks: ## Verify the four owned callback fixture cases through deployed reports
	PYTHONPATH=.:backend $(UV) python scripts/verify_callback_lab.py
