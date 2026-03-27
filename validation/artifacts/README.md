# Validation Artifacts

This directory is written by:

```bash
./venv/bin/python validation/run_validation.py
```

Each lab writes:

- `result.json`: raw scenario output
- `evaluation.json`: pass/fail comparison against `validation/expected/*.json`
- `bundle.json`: combined lab + evaluation snapshot

The runner also writes:

- `summary.json`: overall gate result across all selected labs

These files are intentionally generated artifacts and can be refreshed at any time.
