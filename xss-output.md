# XSS and Output Encoding

**CWE:** CWE-79 (Cross-site Scripting)
**OWASP:** A03:2021 Injection

## Overview

XSS occurs when user-controlled data is rendered in HTML without proper escaping. Python web frameworks provide auto-escaping, but it can be bypassed.

## Jinja2 XSS (Flask, FastAPI)

### BAD - Disabling Auto-Escape

```python
from jinja2 import Environment

# VULNERABLE: Autoescape disabled
env = Environment(autoescape=False)

# VULNERABLE: |safe filter on user input
template = """<div>{{ user_bio|safe }}</div>"""  # XSS if user_bio contains script

# VULNERABLE: Markup() on user input
from markupsafe import Markup
html = Markup(user_input)  # Marks as safe, bypasses escaping
```

### GOOD - Proper Escaping

```python
from jinja2 import Environment, select_autoescape

# SAFE: Autoescape enabled (default for html/xml)
env = Environment(
    autoescape=select_autoescape(['html', 'htm', 'xml'])
)

# SAFE: Let Jinja2 escape automatically
template = """<div>{{ user_bio }}</div>"""  # Auto-escaped

# SAFE: Escape explicitly when needed
from markupsafe import escape
safe_text = escape(user_input)
```

## Django XSS

### BAD - Bypassing Django's Escaping

```python
from django.utils.safestring import mark_safe

# VULNERABLE: mark_safe on user input
def render_comment(comment):
    return mark_safe(comment.text)  # XSS!

# VULNERABLE: |safe filter in template
# template: {{ user_comment|safe }}

# VULNERABLE: format_html with unescaped user data
from django.utils.html import format_html
html = format_html("<div>{}</div>", mark_safe(user_input))  # Still XSS
```

### GOOD - Django's Auto-Escaping

```python
from django.utils.html import escape, format_html

# SAFE: Default template behavior (auto-escaped)
# template: {{ user_comment }}

# SAFE: format_html escapes arguments automatically
html = format_html("<div>{}</div>", user_input)  # Escaped

# SAFE: Explicit escaping
safe_text = escape(user_input)

# SAFE: Only mark_safe for trusted, generated HTML
html = format_html(
    "<a href='{}'>Profile</a>",
    reverse('profile', args=[user.id])  # Generated URL, not user input
)
```

## URL-Based XSS

### BAD - Rendering User URLs Without Validation

```python
# VULNERABLE: User-controlled URLs can use javascript: scheme
template = """<a href="{{ user_url }}">Link</a>"""
# Attacker sets user_url = "javascript:alert(1)"
```

### GOOD - URL Scheme Validation

```python
from urllib.parse import urlparse

def safe_url(url: str) -> str:
    """Validate URL scheme to prevent javascript: XSS."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https', ''):
        return '#'  # Safe fallback
    return url

# In template or view
safe_link = safe_url(user_url)
```

## JSON in HTML Context

### BAD - Unsafe JSON Embedding

```python
# VULNERABLE: JSON can contain </script> breaking out of context
template = """
<script>
    var data = {{ user_data|tojson }};
</script>
"""
# If user_data contains "</script><script>alert(1)</script>"
```

### GOOD - Safe JSON Embedding

```python
import json

# SAFE: Django's json_script tag
# template: {{ user_data|json_script:"user-data" }}

# SAFE: Manual escaping for JSON in HTML
def safe_json_embed(data):
    """Escape JSON for safe embedding in HTML script tags."""
    json_str = json.dumps(data)
    # Escape characters that could break out of script context
    return json_str.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')

# In Jinja2, use tojson with proper escaping
env.policies['json.dumps_kwargs'] = {'sort_keys': True}
```

## Content Security Policy (CSP)

### Adding CSP Headers

```python
# Django middleware
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    # ...
]

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")  # Avoid if possible

# Flask
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'",
})

# FastAPI
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

@app.middleware("http")
async def add_csp_header(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

## Quick Reference

| Context | Escape Method |
|---------|---------------|
| HTML body | Auto-escape (default) |
| HTML attribute | Auto-escape + quote attributes |
| URL | Validate scheme (http/https only) |
| JavaScript | `json.dumps()` + escape `</` |
| CSS | Avoid user input in CSS |

| Framework | Auto-Escape | Bypass to Avoid |
|-----------|-------------|-----------------|
| Jinja2 | `autoescape=True` | `\|safe`, `Markup()` |
| Django | Default on | `\|safe`, `mark_safe()` |
