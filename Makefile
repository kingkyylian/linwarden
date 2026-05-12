.PHONY: test compile smoke smoke-sarif check

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests

compile:
	PYTHONPYCACHEPREFIX=.pycache python3 -m compileall -q src tests

smoke:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m linwarden scan --root tests/fixtures/linux-root --format markdown --fail-on off

smoke-sarif:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m linwarden scan --root tests/fixtures/linux-root --config tests/fixtures/linwarden.json --format sarif --fail-on critical

check: test compile smoke smoke-sarif
