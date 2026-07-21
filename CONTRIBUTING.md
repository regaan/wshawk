# Contributing to WSHawk

Thank you for your interest in contributing to WSHawk! This document provides guidelines for contributing to the project.

## Ways to Contribute

- Report bugs and security issues
- Suggest new features or improvements
- Submit bug fixes
- Add new vulnerability detection modules
- Improve documentation
- Add new payload collections
- Create plugins

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/wshawk.git
   cd wshawk
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   # Linux/macOS
   source venv/bin/activate
   # Windows PowerShell: venv\Scripts\Activate.ps1
   ```

4. Install dependencies:
   ```bash
   python -m pip install -e ".[browser,dev]"
   ```

   Install Chromium only when working on browser-assisted verification:
   ```bash
   playwright install chromium
   ```

5. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use type hints where applicable
- Add docstrings to all functions and classes
- Keep functions focused and modular

### Testing

Before submitting a pull request:

1. Run the Python, lint, and focused type checks:
   ```bash
   python -m unittest discover -s tests
   python -m ruff check .
   python -m mypy
   ```

2. If desktop or extension code changed, run the locked JavaScript checks and audits:
   ```bash
   cd desktop
   npm ci
   npm test
   npm audit --omit=dev --audit-level=moderate
   npm audit --audit-level=moderate
   npm run smoke
   ```

3. Run `python -m pip_audit --progress-spinner off` after changing Python dependencies.
4. Run `python scripts/release_security_checks.py` for packaging, renderer, bridge, authentication, or release changes.
5. Run `python scripts/verify_pyinstaller_hiddenimports.py` when changing the desktop sidecar or its dependencies.
6. Ensure all existing tests pass and add regression tests for changed behavior.

### Commit Messages

Use clear, descriptive commit messages:
- `Add: New feature description`
- `Fix: Bug description`
- `Update: What was updated`
- `Docs: Documentation changes`

## Submitting Changes

1. Commit your changes:
   ```bash
   git add .
   git commit -m "Add: Description of your changes"
   ```

2. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Create a Pull Request on GitHub

### Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Include test results if applicable
- Update documentation if needed

## Adding New Features

### New Vulnerability Detection Module

1. Create a new file in `wshawk/`
2. Follow the existing module structure
3. Add detection logic with proper error handling
4. Include CVSS scoring
5. Add to scanner integration

### New Mutation Strategy

1. Create a new mutator in `wshawk/mutators/`
2. Inherit from `BaseMutator`
3. Implement the `mutate()` method
4. Add to `create_default_mutators()` in `wshawk/mutators/__init__.py`

### New Payload Collection

1. Add payload file to `payloads/` directory
2. Use `.txt` format (one payload per line)
3. Update `WSPayloads` class in `wshawk/__main__.py`

## Reporting Bugs

When reporting bugs, include:

- WSHawk version
- Python version
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages or logs

Use the GitHub issue tracker: https://github.com/regaan/wshawk/issues

## Security Issues

**Do not** report security vulnerabilities in public issues.

Instead, email: security@rothackers.com

Only test systems you own or are explicitly authorized to assess. Pull requests must not include live credentials, captured third-party data, or payload evidence from unauthorized targets.

## Code of Conduct

- Be respectful and professional
- Welcome newcomers
- Focus on constructive feedback
- Respect different viewpoints

## Questions?

- Open a GitHub Discussion
- Check existing issues and documentation
- Review the docs/ folder

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.

---

Thank you for contributing to WSHawk!
