# Pull request

## Summary

Describe the change, motivation, and related issue (`Fixes #...`).

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Breaking change
- [ ] Documentation
- [ ] Security fix

## Verification

List the operating systems and commands used. Include relevant screenshots for desktop UI changes.

- [ ] `python -m unittest discover -s tests`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy`
- [ ] `npm test` (desktop/extension changes)
- [ ] Both npm audits pass (dependency changes)
- [ ] `python -m pip_audit --progress-spinner off` (Python dependency changes)
- [ ] `npm run smoke` (desktop/runtime changes)
- [ ] `python scripts/release_security_checks.py` (security/release changes)
- [ ] `python scripts/verify_pyinstaller_hiddenimports.py` (desktop sidecar changes)

## Checklist

- [ ] I tested only systems I own or am authorized to assess.
- [ ] I added or updated regression tests for changed behavior.
- [ ] I updated documentation and release metadata where needed.
- [ ] I did not include credentials or captured third-party data.
- [ ] New and existing checks pass locally.
