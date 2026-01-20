# Dependency Security

**CWE:** CWE-1104 (Use of Unmaintained Third-Party Components), CWE-1357 (Reliance on Uncontrolled Component)
**OWASP:** A06:2021 Vulnerable and Outdated Components

## Slopsquatting (AI-Suggested Fake Packages)

### The Threat

AI models may hallucinate package names that don't exist. Attackers register these names with malicious code.

### BAD - Blindly Installing AI Suggestions

```bash
# AI suggests: pip install django-rest-validator
# But this package doesn't exist or is malicious!

# AI suggests: pip install flask-security-utils
# Sounds real, but verify first!
```

### GOOD - Verify Before Installing

```bash
# 1. Check if package exists on PyPI
pip index versions django-rest-framework  # Real package

# 2. Check download stats (popular packages have many downloads)
# Visit https://pypistats.org/packages/django-rest-framework

# 3. Check package age and maintainer
# Visit https://pypi.org/project/django-rest-framework/

# 4. Verify official documentation links to this package
```

**Red flags:**
- Package has very few downloads
- Package was created recently
- No link from official framework documentation
- Name is suspiciously similar to popular package

## Typosquatting

### BAD - Misspelled Package Names

```bash
# VULNERABLE: Common typos that may be malicious
pip install reqeusts      # Should be: requests
pip install djagno        # Should be: django
pip install flaask        # Should be: flask
pip install crytography   # Should be: cryptography
pip install urlib3        # Should be: urllib3
```

### GOOD - Verify Package Names

```bash
# SAFE: Double-check spelling against official docs
pip install requests
pip install django
pip install flask
pip install cryptography

# Use copy-paste from official documentation when possible
```

## Vulnerable Dependencies

### BAD - No Security Auditing

```bash
# VULNERABLE: Never checking for known vulnerabilities
pip install -r requirements.txt
# Deploy and forget...
```

### GOOD - Regular Security Audits

```bash
# SAFE: Use pip-audit (from PyPA)
pip install pip-audit
pip-audit

# SAFE: Use safety (requires free API key for full database)
pip install safety
safety check

# SAFE: GitHub Dependabot (enable in repository settings)

# SAFE: In CI/CD pipeline
# .github/workflows/security.yml
# - name: Audit dependencies
#   run: pip-audit --strict
```

## Unpinned Dependencies

### BAD - Loose Version Constraints

```
# requirements.txt - VULNERABLE

requests          # Any version - could break or have vulns
django>=3.0       # Too broad - major versions may break
flask             # No version at all
```

### GOOD - Pinned Dependencies

```
# requirements.txt - SAFE

requests==2.31.0
django==4.2.7
flask==3.0.0
cryptography==41.0.7

# Or use ranges carefully
django>=4.2,<5.0   # Within same major version
```

```bash
# Generate pinned requirements
pip freeze > requirements.txt

# Use pip-tools for better management
pip install pip-tools
pip-compile requirements.in  # Generates pinned requirements.txt
```

## Dependency Confusion

### The Threat

Attackers upload packages with same name as internal packages to public PyPI.

### BAD - No Index Configuration

```bash
# VULNERABLE: pip may fetch from public PyPI instead of private index
pip install internal-company-utils
```

### GOOD - Explicit Index Configuration

```bash
# SAFE: Specify index explicitly
pip install --index-url https://pypi.company.com/simple/ internal-company-utils

# SAFE: pip.conf configuration
# [global]
# index-url = https://pypi.company.com/simple/
# extra-index-url = https://pypi.org/simple/

# SAFE: Use namespaced packages
pip install company-internal-utils  # Namespace prefix
```

## Supply Chain Best Practices

### Lock File Usage

```bash
# Use pip-tools
pip-compile requirements.in --generate-hashes

# requirements.txt output includes hashes:
# requests==2.31.0 \
#     --hash=sha256:58cd2187...
```

### CI/CD Security Checks

```yaml
# .github/workflows/security.yml
name: Security Check

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install pip-audit
      - run: pip-audit --strict --require-hashes -r requirements.txt
```

## Quick Reference

| Threat | Detection | Prevention |
|--------|-----------|------------|
| Slopsquatting | Check PyPI, downloads, age | Verify against official docs |
| Typosquatting | Spell check | Copy from official sources |
| Vulnerable deps | `pip-audit`, `safety` | Regular audits, Dependabot |
| Unpinned deps | Check requirements.txt | Pin versions, use pip-tools |
| Dependency confusion | Audit installed packages | Explicit index config |

## Tools Summary

```bash
# Security auditing
pip-audit                 # PyPA official tool
safety check             # Alternative (needs API key for full DB)

# Dependency management
pip-tools                # pip-compile, pip-sync
pip freeze               # Generate current versions

# Verification
pip index versions PKG   # Check if package exists
pip show PKG            # Show installed package info
```
