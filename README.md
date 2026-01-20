# Security Anti-Patterns for Python

A skill for AI coding assistants that catches insecure patterns before they end up in your Django, Flask, or FastAPI code.

## Supported platforms

| Platform | Status |
|----------|--------|
| Claude Code | Supported |
| Antigravity | TODO |
| Codex | TODO |

## What it does

When you're writing Python web application code, this skill watches for common security mistakes and fixes them on the fly. It covers OWASP Top 10 Web and API Security vulnerabilities with CWE references.

## Installation

### Claude Code

Clone to your personal skills directory:

```bash
git clone https://github.com/subhashdasyam/security-antipatterns-python ~/.claude/skills/security-antipatterns-python
```

For project-specific use, clone to `.claude/skills/` in your repo instead.

### Other platforms

Instructions coming once support is added.

## Coverage

The skill has 11 modules:

- **injection.md** - SQL injection, command injection, template injection
- **deserialization.md** - pickle, yaml, marshal (the Python-specific traps)
- **xss-output.md** - Cross-site scripting and template escaping
- **auth-access.md** - Broken access control, BOLA, sessions
- **crypto-secrets.md** - Password hashing, secrets, encryption
- **input-validation.md** - Pydantic validation, forms, file uploads
- **file-operations.md** - Path traversal, temp file handling
- **django-security.md** - CSRF, settings, ORM gotchas
- **fastapi-flask.md** - Auth patterns, CORS, dependency injection
- **dependencies.md** - pip audit, typosquatting
- **python-runtime.md** - eval/exec dangers, ReDoS

## The short version

Never use f-strings in SQL queries. Never `pickle.loads()` untrusted data. Never `yaml.load()` (use `safe_load`). Never `os.system()` with user input. Never use `random` for security stuff (use `secrets`). Never use MD5 or SHA1 for passwords.

Each module has BAD and GOOD code examples so you can see exactly what to avoid.

## When it activates

Any time you're generating:
- Django views or ORM queries
- Flask routes
- FastAPI endpoints
- SQLAlchemy queries
- File handling code
- Authentication or session logic
- Anything deserializing external data

## License

MIT
