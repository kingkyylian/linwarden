# Examples

Generate a Markdown report from the included fixture:

```bash
PYTHONPATH=src python3 -m linwarden scan \
  --root tests/fixtures/linux-root \
  --format markdown \
  --output examples/fixture-report.md
```

Generate a JSON report:

```bash
PYTHONPATH=src python3 -m linwarden scan \
  --root tests/fixtures/linux-root \
  --format json \
  --output examples/fixture-report.json
```
