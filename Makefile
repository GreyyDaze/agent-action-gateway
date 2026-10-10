# Developer verification and day-to-day tasks.
#
# The proof and chaos suites verify this library's own behaviour, not an
# adopter's integration, so they live here rather than in the installed `safety`
# CLI. Evidence about the library is published in the README badge and
# docs/history/release-proof.md; these targets are how a contributor produces it.
#
# `make` is optional. Every target below is a thin wrapper, so the underlying
# command works on its own wherever make is unavailable:
#
#     python -m safety_layer.proofs.proof --jobs 1000
#     python -m safety_layer.proofs.chaos --jobs 1000

PYTHON ?= python
JOBS   ?= 1000

.PHONY: help proof chaos verify test lint typecheck quickstart wheel clean \
        verify-boundary doctor

help:
	@echo "verify      ruff, mypy and the full test suite"
	@echo "proof       run every guarantee suite (about this library)"
	@echo "chaos       crash-injection suite (about this library)"
	@echo "test        the test suite on its own"
	@echo "lint        ruff"
	@echo "typecheck   mypy"
	@echo "quickstart  run the documented example"
	@echo "wheel       build the wheel"
	@echo ""
	@echo "Adopter deployment (about your setup, not this library):"
	@echo "  verify-boundary  probe the gateway topology from the agent's position"
	@echo "  doctor          check this host's gateway configuration"

verify: lint typecheck test

# Verifies the DEPLOYMENT, not the library: it attaches an ephemeral container
# to the same network your agent occupies and tries to reach a provider, read
# the secret, and call the gateway without a key. Exits 2 when it cannot run at
# all -- never 0, because "could not check" is not "passed".
verify-boundary:
	@command -v docker >/dev/null 2>&1 || { \
	  echo "INCONCLUSIVE: docker is not available, so the deployment boundary was not tested."; \
	  echo "  This says nothing about whether your setup is safe."; \
	  exit 2; }
	@cd deploy && docker compose up -d gateway
	@cd deploy && SAFETY_MASTER_KEY=$${SAFETY_MASTER_KEY:-} \
	  docker compose run --rm --no-deps --network agent_net \
	    -v "$$(pwd)/verify_boundary.py:/probe.py:ro" \
	    -e SAFETY_PROBE_KEY="$${SAFETY_PROBE_KEY:-}" \
	    python:3.12-slim python /probe.py --gateway http://gateway:8080

doctor:
	$(PYTHON) -m safety_layer.interface.cli gateway doctor \
	  --config deploy/routes.example.json

proof:
	$(PYTHON) -m safety_layer.proofs.proof --jobs $(JOBS)

chaos:
	$(PYTHON) -m safety_layer.proofs.chaos --jobs $(JOBS)

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
