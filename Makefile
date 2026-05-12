.PHONY: test compile smoke

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests

compile:
	PYTHONPYCACHEPREFIX=.pycache python3 -m compileall -q src tests

smoke:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m linwarden scan --root tests/fixtures/linux-root --format markdown --fail-on off
