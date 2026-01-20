# FastAPI and Flask Security

**Framework-Specific Security Patterns for FastAPI and Flask**

## FastAPI Authentication

### BAD - Missing or Weak Auth

```python
from fastapi import FastAPI

app = FastAPI()

# VULNERABLE: No authentication
@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    return db.get_user(user_id)  # Anyone can access!

# VULNERABLE: Weak token validation
@app.get("/api/admin")
def admin(token: str = None):
    if token == "admin123":  # Hardcoded token!
        return {"admin": True}
```

### GOOD - Proper FastAPI Auth

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
import os

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = os.environ["JWT_SECRET_KEY"]

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db.get_user(user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# SAFE: Protected endpoint
@app.get("/api/users/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

# SAFE: Role-based protection
async def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return current_user

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, admin: User = Depends(get_admin_user)):
    await db.delete_user(user_id)
```

## FastAPI Input Validation

### BAD - No Validation

```python
# VULNERABLE: Accepting raw dict
@app.post("/api/users")
def create_user(data: dict):
    user = User(**data)  # Mass assignment, no validation!
    db.add(user)
```

### GOOD - Pydantic Validation

```python
from pydantic import BaseModel, EmailStr, Field, field_validator

class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8)

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    # password intentionally excluded from response

@app.post("/api/users", response_model=UserResponse)
def create_user(user: CreateUserRequest):
    # Validated input, controlled output
    return db.create_user(user)
```

## Flask Secret Key

### BAD - Weak or Missing Secret

```python
from flask import Flask

app = Flask(__name__)

# VULNERABLE: Default or weak secret
app.secret_key = 'dev'

# VULNERABLE: No secret key (sessions won't work securely)
# app.secret_key not set
```

### GOOD - Strong Secret Key

```python
import os
from flask import Flask

app = Flask(__name__)

# SAFE: Strong secret from environment
app.secret_key = os.environ['FLASK_SECRET_KEY']

# Generate strong secret: python -c "import secrets; print(secrets.token_hex(32))"
```

## Flask Session Security

### BAD - Client-Side Session Exposure

```python
# VULNERABLE: Sensitive data in Flask's client-side sessions
from flask import session

@app.route('/login')
def login():
    session['password_hash'] = user.password_hash  # Visible in cookie!
    session['internal_role_id'] = 99  # Can be tampered
```

### GOOD - Server-Side Sessions

```python
from flask import Flask, session
from flask_session import Session
import redis

app = Flask(__name__)

# SAFE: Server-side session storage
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(os.environ['REDIS_URL'])
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

Session(app)

# Now sensitive data stays server-side
@app.route('/login')
def login():
    session['user_id'] = user.id  # Only ID stored, lookup on server
```

## CORS Configuration

### BAD - Overly Permissive CORS

```python
# FastAPI
from fastapi.middleware.cors import CORSMiddleware

# VULNERABLE: Allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  # Dangerous with wildcard!
    allow_methods=["*"],
    allow_headers=["*"],
)

# Flask
from flask_cors import CORS

# VULNERABLE: Allow all origins
CORS(app, origins="*", supports_credentials=True)
```

### GOOD - Restrictive CORS

```python
# FastAPI - SAFE
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    "https://myapp.com",
    "https://www.myapp.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Flask - SAFE
from flask_cors import CORS

CORS(app, origins=["https://myapp.com"], supports_credentials=True)
```

## Rate Limiting

### BAD - No Rate Limiting

```python
# VULNERABLE: No protection against brute force
@app.post("/login")
def login(username: str, password: str):
    user = authenticate(username, password)
    # Attacker can try unlimited passwords
```

### GOOD - Rate Limited Endpoints

```python
# FastAPI with slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, username: str, password: str):
    user = authenticate(username, password)

# Flask with flask-limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    user = authenticate(request.form['username'], request.form['password'])
```

## Error Handling

### BAD - Leaking Stack Traces

```python
# VULNERABLE: Debug mode in production
app = FastAPI(debug=True)  # Stack traces exposed!

# VULNERABLE: Unhandled exceptions leak info
@app.get("/user/{user_id}")
def get_user(user_id: int):
    return db.query(User).filter(User.id == user_id).one()  # NoResultFound exposes query
```

### GOOD - Safe Error Handling

```python
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(debug=False)

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    # Log full error internally
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    # Return generic message to client
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

@app.get("/user/{user_id}")
def get_user(user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

## Quick Reference

| Issue | FastAPI | Flask |
|-------|---------|-------|
| Auth | `Depends(get_current_user)` | `@login_required` |
| Validation | Pydantic models | WTForms / Marshmallow |
| Sessions | JWT / server-side | flask-session (server-side) |
| CORS | CORSMiddleware with explicit origins | flask-cors with explicit origins |
| Rate Limit | slowapi | flask-limiter |
| Secret | N/A (JWT secret in env) | `app.secret_key` from env |
