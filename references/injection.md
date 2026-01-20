# Injection Vulnerabilities

**CWE:** CWE-89 (SQL), CWE-78 (OS Command), CWE-90 (LDAP), CWE-1336 (Template)
**OWASP:** A03:2021 Injection

## SQL Injection (CWE-89)

### BAD - String Interpolation in SQL

```python
# VULNERABLE: f-string in raw SQL
def get_user(user_id: str):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # SQL injection!

# VULNERABLE: .format() in SQL
query = "SELECT * FROM users WHERE name = '{}'".format(username)

# VULNERABLE: % formatting
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)  # Still vulnerable - substitution before execute
```

### GOOD - Parameterized Queries

```python
# SAFE: Parameterized query (DB-API 2.0)
def get_user(user_id: str):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SAFE: SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()

# SAFE: SQLAlchemy Core with bindparam
from sqlalchemy import text
stmt = text("SELECT * FROM users WHERE id = :user_id")
result = conn.execute(stmt, {"user_id": user_id})

# SAFE: Django ORM
user = User.objects.get(id=user_id)
users = User.objects.filter(name__icontains=search_term)
```

## Command Injection (CWE-78)

### BAD - Shell Execution with User Input

```python
# VULNERABLE: os.system with user input
os.system(f"ls {user_directory}")

# VULNERABLE: shell=True with user input
subprocess.run(f"grep {pattern} {filename}", shell=True)

# VULNERABLE: Popen with shell=True
subprocess.Popen(f"convert {input_file} {output_file}", shell=True)
```

### GOOD - Safe Subprocess Usage

```python
# SAFE: subprocess with list arguments, no shell
subprocess.run(["ls", user_directory], shell=False, check=True)

# SAFE: shlex.quote for unavoidable shell usage (rare)
import shlex
subprocess.run(f"grep {shlex.quote(pattern)} {shlex.quote(filename)}", shell=True)

# SAFE: Use Python libraries instead of shell commands
from pathlib import Path
files = list(Path(user_directory).iterdir())
```

## Template Injection (CWE-1336)

### BAD - User-Controlled Templates

```python
# VULNERABLE: User input as template
from jinja2 import Template
template = Template(user_input)  # SSTI vulnerability!
output = template.render()

# VULNERABLE: Django template from user string
from django.template import Template
t = Template(user_provided_template)
```

### GOOD - Safe Template Usage

```python
# SAFE: Jinja2 sandbox for user templates (if absolutely required)
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_input)

# SAFE: Use predefined templates with user DATA only
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
template = env.get_template("user_page.html")
output = template.render(user_data=user_input)  # Data, not template
```

## LDAP Injection (CWE-90)

### BAD - Unescaped LDAP Filters

```python
# VULNERABLE: Direct string interpolation
filter_str = f"(uid={username})"
conn.search("dc=example,dc=com", filter_str)
```

### GOOD - Escaped LDAP Queries

```python
# SAFE: Use ldap3 escape functions
from ldap3.utils.conv import escape_filter_chars
safe_username = escape_filter_chars(username)
filter_str = f"(uid={safe_username})"
conn.search("dc=example,dc=com", filter_str)
```

## Quick Reference

| Attack | Pattern to Avoid | Secure Alternative |
|--------|------------------|-------------------|
| SQL Injection | f-strings/format in SQL | Parameterized queries, ORM |
| Command Injection | `shell=True`, `os.system()` | `subprocess.run([...], shell=False)` |
| Template Injection | `Template(user_input)` | Predefined templates, sandbox |
| LDAP Injection | Unescaped filter strings | `escape_filter_chars()` |
