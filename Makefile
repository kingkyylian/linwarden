.PHONY: test compile lint typecheck smoke smoke-sarif package check

PYTHON ?= python3

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m unittest discover -s tests

compile:
	PYTHONPYCACHEPREFIX=.pycache $(PYTHON) -m compileall -q src tests scripts

lint:
	$(PYTHON) -m ruff check src tests scripts

typecheck:
	$(PYTHON) -m mypy

smoke:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m linwarden scan --root tests/fixtures/linux-root --format markdown --fail-on off

smoke-sarif:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m linwarden scan --root tests/fixtures/linux-root --config tests/fixtures/linwarden.json --format sarif --fail-on critical

package:
	$(PYTHON) -m build

check: test compile lint typecheck smoke smoke-sarif
