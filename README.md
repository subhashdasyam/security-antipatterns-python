# Security Anti-Patterns for Python

AI coding agents write insecure code. Not maliciously - they just optimize for "works" over "safe." This skill fixes that.

## The problem

Ask Claude, Codex, or any AI to build a login form. You'll probably get something like:

```python
# AI-generated code - looks fine, isn't
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)  # SQL injection waiting to happen
```

The AI didn't know better. It generated statistically likely Python code. Unfortunately, statistically likely often means copied from Stack Overflow circa 2015.

This skill teaches the AI to catch these patterns and fix them before they hit your codebase.

## What it catches

11 modules covering OWASP Top 10 Web and API vulnerabilities:

| Module | What it prevents |
|--------|------------------|
| injection.md | SQL injection, command injection, template injection |
| deserialization.md | pickle attacks, unsafe yaml.load |
| xss-output.md | Cross-site scripting, missing template escaping |
| auth-access.md | Broken access control, BOLA, session issues |
| crypto-secrets.md | Weak hashing, hardcoded secrets, bad randomness |
| input-validation.md | Missing validation, file upload attacks, mass assignment |
| file-operations.md | Path traversal, temp file races |
| django-security.md | CSRF bypass, unsafe settings, ORM gotchas |
| fastapi-flask.md | Auth patterns, CORS misconfiguration |
| dependencies.md | Supply chain attacks, typosquatting |
| python-runtime.md | eval/exec dangers, ReDoS |

## The short version

- Never f-strings in SQL. Use parameterized queries.
- Never `pickle.loads()` on untrusted data. Use JSON.
- Never `yaml.load()`. Use `yaml.safe_load()`.
- Never `os.system()` with user input. Use `subprocess.run()` with a list.
- Never `random` for security. Use `secrets`.
- Never MD5/SHA1 for passwords. Use bcrypt or argon2.

Each module has bad and good examples so you can see exactly what to avoid.

## Supported platforms

| Platform | Status |
|----------|--------|
| Claude Code | Works |
| OpenAI Codex | Works |
| Google Antigravity | Works |
| Warp | Works |
| VS Code Copilot | Works |

This skill follows the [Agent Skills open standard](https://agentskills.io/). If your AI tool supports skills, this works.

## Installation

### Claude Code

Clone to your skills directory:

```bash
git clone https://github.com/subhashdasyam/security-antipatterns-python ~/.claude/skills/security-antipatterns-python
```

Or for a specific project, clone to `.claude/skills/` in the repo.

### OpenAI Codex CLI

```bash
mkdir -p ~/.codex/skills
ln -s $(pwd) ~/.codex/skills/security-antipatterns-python
```

### Google Antigravity

```bash
mkdir -p ~/.antigravity/skills
ln -s $(pwd) ~/.antigravity/skills/security-antipatterns-python
```

### Warp Terminal

Copy to `~/.warp/skills/` or configure the skill path in Warp settings.

### VS Code Copilot

Copy the skill folder to `.github/skills/` in your project.

### Any other tool

Copy or symlink this folder to wherever your AI tool looks for skills. The format is standard - it should just work.

## When it activates

The skill kicks in when you're generating:

- Django views or ORM queries
- Flask routes
- FastAPI endpoints
- SQLAlchemy queries
- File handling code
- Authentication or session logic
- Anything deserializing external data

## License

MIT
