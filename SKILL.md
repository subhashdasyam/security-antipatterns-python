---
name: security-antipatterns-python
description: Use when generating Python code for web applications, APIs, or handling user input - prevents OWASP Top 10 vulnerabilities in Django, Flask, FastAPI
version: "1.0.0"
allowed-tools: "Read"
---

# Security Anti-Patterns Guard for Python

## Overview

Code generation guard that prevents security vulnerabilities while writing Python web application code. Covers OWASP Top 10 Web (2021), OWASP API Security Top 10 (2023), with CWE references throughout.

**Stack:** Python, Django, Flask, FastAPI, SQLAlchemy, Pydantic

## When to Activate

Activate when generating code that:
- Handles user input (forms, API requests, file uploads)
- Queries databases (SQL, ORM operations)
- Performs authentication or authorization
- Manages sessions or tokens
- Processes files or paths
- Serializes/deserializes data
- Uses cryptographic operations
- Executes system commands

## Critical Rules (Top 10)

1. **NEVER** use f-strings or `.format()` in SQL queries - use parameterized queries or ORM
2. **NEVER** use `pickle.loads()` on untrusted data - use JSON with schema validation
3. **NEVER** use `eval()`, `exec()`, or `compile()` on user input
4. **NEVER** use `os.system()` or `shell=True` with user data - use `subprocess.run()` with list args
5. **NEVER** use `yaml.load()` - use `yaml.safe_load()`
6. **NEVER** hardcode secrets - use environment variables
7. **NEVER** use `random` for security - use `secrets` module
8. **NEVER** use `md5` or `sha1` for passwords - use `bcrypt` or `argon2`
9. **NEVER** trust user-supplied file paths - validate with `pathlib` and check resolved path
10. **NEVER** skip authorization checks - always verify user owns/can access the resource

## Module Index

| Module | Focus | Key Vulnerabilities |
|--------|-------|---------------------|
| [{baseDir}/references/injection.md]({baseDir}/references/injection.md) | SQL, Command, Template, LDAP | CWE-89, CWE-78, CWE-90, CWE-1336 |
| [{baseDir}/references/deserialization.md]({baseDir}/references/deserialization.md) | pickle, yaml, marshal | CWE-502 |
| [{baseDir}/references/xss-output.md]({baseDir}/references/xss-output.md) | XSS, template escaping | CWE-79 |
| [{baseDir}/references/auth-access.md]({baseDir}/references/auth-access.md) | BOLA, BFLA, sessions | CWE-862, CWE-863, CWE-287 |
| [{baseDir}/references/crypto-secrets.md]({baseDir}/references/crypto-secrets.md) | Secrets, hashing, encryption | CWE-798, CWE-327, CWE-916 |
| [{baseDir}/references/input-validation.md]({baseDir}/references/input-validation.md) | Pydantic, forms, uploads | CWE-20, CWE-434, CWE-915 |
| [{baseDir}/references/file-operations.md]({baseDir}/references/file-operations.md) | Path traversal, temp files | CWE-22, CWE-377 |
| [{baseDir}/references/django-security.md]({baseDir}/references/django-security.md) | CSRF, settings, ORM | Django-specific |
| [{baseDir}/references/fastapi-flask.md]({baseDir}/references/fastapi-flask.md) | Auth, CORS, validation | FastAPI/Flask-specific |
| [{baseDir}/references/dependencies.md]({baseDir}/references/dependencies.md) | pip audit, typosquatting | CWE-1104, CWE-1357 |
| [{baseDir}/references/python-runtime.md]({baseDir}/references/python-runtime.md) | eval/exec, ReDoS | CWE-94, CWE-1333 |

## Quick Decision Tree

```
User input involved?
├─ Database query → See {baseDir}/references/injection.md (use ORM/parameterized)
├─ File path → See {baseDir}/references/file-operations.md (use pathlib + resolve check)
├─ Command execution → See {baseDir}/references/injection.md (subprocess with list args)
├─ Deserialization → See {baseDir}/references/deserialization.md (NEVER pickle untrusted)
├─ Template rendering → See {baseDir}/references/xss-output.md (auto-escape enabled)
└─ API endpoint → See {baseDir}/references/auth-access.md + {baseDir}/references/input-validation.md

Storing/generating secrets?
├─ API keys → See {baseDir}/references/crypto-secrets.md (env vars)
├─ Passwords → See {baseDir}/references/crypto-secrets.md (bcrypt/argon2)
└─ Tokens → See {baseDir}/references/crypto-secrets.md (secrets module)

Framework-specific?
├─ Django → See {baseDir}/references/django-security.md
├─ FastAPI → See {baseDir}/references/fastapi-flask.md
└─ Flask → See {baseDir}/references/fastapi-flask.md
```

## How to Use This Skill

1. **During code generation:** Reference relevant module for specific vulnerability patterns
2. **Code review:** Check generated code against patterns in each module
3. **When uncertain:** Default to the more secure option; add explicit comments explaining security decisions

## Sources

- [OWASP Python Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [FastAPI Security Tutorial](https://fastapi.tiangolo.com/tutorial/security/)
- [Bandit - Python Security Linter](https://bandit.readthedocs.io/)
- [PEP 506 - secrets module](https://peps.python.org/pep-0506/)
