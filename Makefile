# Developer verification and day-to-day tasks.
#
# The proof and chaos suites verify this library's own behaviour, not an
# adopter's integration, so they live here rather than in the installed `agent-gateway`
# CLI. Evidence about the library is published in the README badge; these
# targets are how a contributor produces it.
#
# `make` is optional. Every target below is a thin wrapper, so the underlying
# command works on its own wherever make is unavailable:
#
#     python -m agent_action_gateway.proofs.proof --jobs 1000
#     python -m agent_action_gateway.proofs.chaos --jobs 1000

PYTHON ?= python
JOBS   ?= 1000

.PHONY: help proof chaos verify test test-unit test-integration test-evals \
        mutation verify-full lint typecheck quickstart wheel clean \
        verify-boundary doctor

help:
	@echo "verify      ruff, mypy and the full test suite"
	@echo "verify-full verify + mutation + proof + chaos"
	@echo "proof       run every guarantee suite (about this library)"
	@echo "chaos       crash-injection suite (about this library)"
	@echo "mutation    mutmut: full mutation score on safety code (nightly)"
	@echo "test        the full test suite"
	@echo "test-unit   pure, fast tests only"
	@echo "test-integration  database/socket/server tests"
	@echo "test-evals  quality/evaluation suites"
	@echo "lint        ruff"
	@echo "typecheck   mypy"
	@echo "quickstart  run the documented example"
	@echo "wheel       build the wheel"
	@echo ""
	@echo "Adopter deployment (about your setup, not this library):"
	@echo "  verify-boundary  probe the gateway topology from the agent's position"
	@echo "  doctor          check this host's gateway configuration"

verify: lint typecheck test

# Test lanes by speed (markers assigned in tests/conftest.py).
test-unit:
	$(PYTHON) -m pytest -q -m unit

test-integration:
	$(PYTHON) -m pytest -q -m integration

test-evals:
	$(PYTHON) -m pytest -q -m evals

# Mutation testing: full automatic check that tests detect changed behavior.
# mutmut covers all safety code and reports survivors. Nightly, not per commit.
mutation:
	$(PYTHON) -m mutmut run
	$(PYTHON) -m mutmut export-cicd-stats

# Full verification including the slower mutation gate.
verify-full: verify mutation proof chaos

# Verifies the DEPLOYMENT, not the library: it attaches an ephemeral container
# to the same network your agent occupies and tries to reach a provider, read
# the secret, and call the gateway without a key. Exits 2 when it cannot run at
# all -- never 0, because "could not check" is not "passed".
#
# Set COMPOSE_FILES to probe a different topology, e.g. the egress override:
#     COMPOSE_FILES="-f docker-compose.yml -f docker-compose.egress.yml" \
#       make verify-boundary
COMPOSE_FILES ?= -f docker-compose.yml
COMPOSE        ?= docker compose $(COMPOSE_FILES)

verify-boundary:
	@command -v docker >/dev/null 2>&1 || { \
	  echo "INCONCLUSIVE: docker is not available, so the deployment boundary was not tested."; \
	  echo "  This says nothing about whether your setup is safe."; \
	  exit 2; }
	@cd deploy && $(COMPOSE) up -d gateway
	@cd deploy && $(COMPOSE) run --rm probe; status=$$?; \
	  if [ $$status -eq 2 ]; then echo "INCONCLUSIVE: the probe could not determine the boundary."; fi; \
	  exit $$status

doctor:
	$(PYTHON) -m agent_action_gateway.cli gateway doctor \
	  --config deploy/routes.example.json

proof:
	$(PYTHON) -m agent_action_gateway.proofs.proof --jobs $(JOBS)

chaos:
	$(PYTHON) -m agent_action_gateway.proofs.chaos --jobs $(JOBS)

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check .

typecheck:
	$(PYTHON) -m mypy

quickstart:
	$(PYTHON) docs/examples/quickstart.py

wheel:
	$(PYTHON) -m build --wheel

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
