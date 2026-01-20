# Authentication and Access Control

**CWE:** CWE-287 (Improper Auth), CWE-384 (Session Fixation), CWE-862 (Missing Auth), CWE-863 (Incorrect Auth)
**OWASP API:** API1:2023 (BOLA), API2:2023 (Broken Auth), API5:2023 (BFLA)

## BOLA - Broken Object Level Authorization (API1:2023)

### BAD - Missing Ownership Check

```python
# VULNERABLE: Fetches any user by ID without checking ownership
@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    return User.objects.get(id=user_id)  # Any user can access any profile!

# VULNERABLE: DRF without permission check
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()  # Returns all users!

# VULNERABLE: Trusting user-supplied IDs
@app.post("/api/orders/{order_id}/cancel")
def cancel_order(order_id: int):
    order = Order.objects.get(id=order_id)  # Attacker can cancel any order
    order.status = "cancelled"
    order.save()
```

### GOOD - Enforce Ownership

```python
# SAFE: Filter by authenticated user
@app.get("/api/users/me")
def get_current_user(current_user: User = Depends(get_current_user)):
    return current_user

# SAFE: Verify ownership before access
@app.post("/api/orders/{order_id}/cancel")
def cancel_order(order_id: int, current_user: User = Depends(get_current_user)):
    order = Order.objects.filter(id=order_id, user=current_user).first()
    if not order:
        raise HTTPException(status_code=404)
    order.status = "cancelled"
    order.save()

# SAFE: DRF with proper filtering
class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)
```

## BFLA - Broken Function Level Authorization (API5:2023)

### BAD - Frontend-Only Role Checks

```python
# VULNERABLE: No server-side role check
@app.delete("/api/users/{user_id}")
def delete_user(user_id: int):
    # Frontend hides this button for non-admins, but no backend check!
    User.objects.filter(id=user_id).delete()
```

### GOOD - Server-Side Permission Checks

```python
# SAFE: Check permissions on backend
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated(current_user: User = Depends(get_current_user), *args, **kwargs):
        if not current_user.is_admin:
            raise HTTPException(status_code=403, detail="Admin required")
        return f(current_user=current_user, *args, **kwargs)
    return decorated

@app.delete("/api/users/{user_id}")
@admin_required
def delete_user(user_id: int, current_user: User):
    User.objects.filter(id=user_id).delete()

# SAFE: DRF permission classes
from rest_framework.permissions import IsAdminUser

class AdminUserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsAdminUser]
```

## JWT Security

### BAD - Weak JWT Implementation

```python
import jwt

# VULNERABLE: Weak secret
token = jwt.encode(payload, "secret", algorithm="HS256")

# VULNERABLE: Not verifying algorithm (algorithm confusion attack)
data = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])  # "none" is dangerous!

# VULNERABLE: Not validating expiration
data = jwt.decode(token, SECRET_KEY, options={"verify_exp": False})
```

### GOOD - Secure JWT Implementation

```python
import jwt
from datetime import datetime, timedelta
import os

SECRET_KEY = os.environ["JWT_SECRET_KEY"]  # Strong, from environment

def create_token(user_id: int) -> str:
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str) -> dict:
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],  # Explicit single algorithm
        options={"require": ["exp", "sub"]}  # Require claims
    )
```

## Session Security

### BAD - Session Fixation

```python
# VULNERABLE: Not rotating session after login
def login(request):
    user = authenticate(request.POST['username'], request.POST['password'])
    if user:
        request.session['user_id'] = user.id  # Session ID unchanged!
```

### GOOD - Session Rotation

```python
# SAFE: Django - cycle session key on login
from django.contrib.auth import login

def login_view(request):
    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)  # Django rotates session automatically

# SAFE: Flask - regenerate session
from flask import session

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session.clear()  # Clear old session
        session['user_id'] = user.id
        session.permanent = True
```

## Missing Authentication

### BAD - Unprotected Endpoints

```python
# VULNERABLE: No authentication required
@app.get("/api/admin/users")
def list_all_users():
    return User.objects.all()

# VULNERABLE: Django view without decorator
def sensitive_view(request):
    return JsonResponse({"data": "sensitive"})
```

### GOOD - Require Authentication

```python
# SAFE: FastAPI dependency
@app.get("/api/admin/users")
def list_all_users(current_user: User = Depends(get_current_admin_user)):
    return User.objects.all()

# SAFE: Django decorator
from django.contrib.auth.decorators import login_required

@login_required
def sensitive_view(request):
    return JsonResponse({"data": "sensitive"})

# SAFE: DRF default authentication
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}
```

## Quick Reference

| Vulnerability | Check | Fix |
|---------------|-------|-----|
| BOLA | User can access others' data? | Filter by `request.user` |
| BFLA | Role check only on frontend? | Server-side permission check |
| Session Fixation | Session unchanged on login? | Rotate session on auth |
| Missing Auth | Endpoint accessible anonymously? | Add `@login_required` or `Depends()` |
| JWT Weak | Hardcoded secret? `none` algorithm? | Env secret, explicit single algorithm |
