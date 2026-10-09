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

.PHONY: help proof chaos verify test lint typecheck quickstart wheel clean

help:
	@echo "verify      ruff, mypy and the full test suite"
	@echo "proof       run every guarantee suite (about this library)"
	@echo "chaos       crash-injection suite (about this library)"
	@echo "test        the test suite on its own"
	@echo "lint        ruff"
	@echo "typecheck   mypy"
	@echo "quickstart  run the documented example"
	@echo "wheel       build the wheel"

verify: lint typecheck test

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
