# Django Security

**Framework-Specific Security Patterns for Django**

## CSRF Protection

### BAD - Disabling CSRF

```python
from django.views.decorators.csrf import csrf_exempt

# VULNERABLE: CSRF disabled on state-changing view
@csrf_exempt
def transfer_money(request):
    # Attacker can forge requests from victim's browser!
    amount = request.POST['amount']
    to_account = request.POST['to_account']
    transfer(request.user, to_account, amount)

# VULNERABLE: Missing CSRF token in form
# <form method="post">
#   <input name="amount">
#   <button>Submit</button>
# </form>
```

### GOOD - Proper CSRF Handling

```python
# SAFE: Use CSRF token in templates
# <form method="post">
#   {% csrf_token %}
#   <input name="amount">
#   <button>Submit</button>
# </form>

# SAFE: For AJAX, include token in headers
# JavaScript:
# const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
# fetch('/api/endpoint/', {
#     method: 'POST',
#     headers: {'X-CSRFToken': csrftoken},
#     body: JSON.stringify(data)
# });

# SAFE: If you must exempt (e.g., webhooks), use other verification
from django.views.decorators.csrf import csrf_exempt
import hmac

@csrf_exempt
def webhook(request):
    # Verify webhook signature instead
    signature = request.headers.get('X-Webhook-Signature')
    if not verify_webhook_signature(request.body, signature):
        return HttpResponseForbidden()
    # Process webhook
```

## Settings Security

### BAD - Insecure Settings

```python
# settings.py

# VULNERABLE: Debug enabled in production
DEBUG = True

# VULNERABLE: Hardcoded secret key
SECRET_KEY = 'django-insecure-abc123def456'

# VULNERABLE: Allow all hosts
ALLOWED_HOSTS = ['*']

# VULNERABLE: Missing security middleware
MIDDLEWARE = [
    # Missing SecurityMiddleware
]

# VULNERABLE: Cookies without security flags
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
```

### GOOD - Secure Settings

```python
# settings.py
import os

# SAFE: Environment-based debug
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

# SAFE: Secret key from environment
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

# SAFE: Explicit allowed hosts
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# SAFE: Security middleware enabled
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware
]

# SAFE: Secure cookies (in production)
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True

# SAFE: Additional security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# SAFE: HTTPS redirect in production
SECURE_SSL_REDIRECT = not DEBUG
```

## ORM Security

### BAD - Raw SQL with User Input

```python
from django.db import connection

# VULNERABLE: String formatting in raw SQL
def search_users(name):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")
        return cursor.fetchall()

# VULNERABLE: extra() with user input
User.objects.extra(where=[f"name = '{user_input}'"])

# VULNERABLE: RawSQL with user input
from django.db.models.expressions import RawSQL
User.objects.annotate(val=RawSQL(f"SELECT {user_column} FROM other", []))
```

### GOOD - Safe ORM Usage

```python
# SAFE: ORM methods handle escaping
def search_users(name):
    return User.objects.filter(name__icontains=name)

# SAFE: Parameterized raw SQL when ORM isn't enough
def search_users_raw(name):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM users WHERE name LIKE %s",
            [f'%{name}%']
        )
        return cursor.fetchall()

# SAFE: Raw SQL with params
User.objects.raw(
    "SELECT * FROM users WHERE id = %s",
    [user_id]
)
```

## Authentication

### BAD - Weak Authentication

```python
# VULNERABLE: Manual password comparison
def login(request):
    user = User.objects.get(username=request.POST['username'])
    if user.password == request.POST['password']:  # Plain text comparison!
        login(request, user)

# VULNERABLE: No rate limiting on login
def login_view(request):
    # Attacker can brute force passwords
    user = authenticate(username=username, password=password)
```

### GOOD - Secure Authentication

```python
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit

# SAFE: Use Django's authentication
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)  # Session rotated automatically
        return redirect('home')
    return render(request, 'login.html', {'error': 'Invalid credentials'})

# SAFE: Protect views
@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

# SAFE: Use Django's password hashing
from django.contrib.auth.hashers import make_password, check_password
hashed = make_password(raw_password)
```

## Clickjacking Protection

### BAD - No Frame Protection

```python
# VULNERABLE: Missing X_FRAME_OPTIONS
# Allows page to be embedded in attacker's iframe
```

### GOOD - Frame Protection

```python
# settings.py
X_FRAME_OPTIONS = 'DENY'  # Or 'SAMEORIGIN' if needed

# For specific views that need framing
from django.views.decorators.clickjacking import xframe_options_sameorigin

@xframe_options_sameorigin
def embeddable_view(request):
    pass
```

## Quick Reference

| Setting | Insecure | Secure |
|---------|----------|--------|
| `DEBUG` | `True` in prod | `False` in prod |
| `SECRET_KEY` | Hardcoded | Environment variable |
| `ALLOWED_HOSTS` | `['*']` | Explicit hosts |
| `SESSION_COOKIE_SECURE` | `False` | `True` in prod |
| `CSRF_COOKIE_SECURE` | `False` | `True` in prod |
| `X_FRAME_OPTIONS` | Not set | `'DENY'` |
| `SECURE_SSL_REDIRECT` | `False` | `True` in prod |

## Security Checklist

```bash
# Run Django's security check
python manage.py check --deploy

# Common issues it catches:
# - DEBUG = True
# - Hardcoded SECRET_KEY
# - Missing SECURE_* settings
# - Missing X_FRAME_OPTIONS
```
