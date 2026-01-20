# Cryptography and Secrets Management

**CWE:** CWE-798 (Hardcoded Credentials), CWE-327 (Broken Crypto), CWE-330 (Weak PRNG), CWE-916 (Weak Password Hash)
**OWASP:** A02:2021 Cryptographic Failures

## Hardcoded Secrets (CWE-798)

### BAD - Secrets in Code

```python
# VULNERABLE: Hardcoded API keys
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://user:password123@localhost/db"

# VULNERABLE: Secrets in config files committed to git
# config.py
SECRET_KEY = "my-secret-key-do-not-share"

# VULNERABLE: Secrets in default arguments
def connect_db(password="admin123"):
    pass
```

### GOOD - Environment Variables

```python
import os
from functools import lru_cache

# SAFE: Load from environment
API_KEY = os.environ["API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]

# SAFE: With validation
def get_required_env(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise ValueError(f"Required environment variable {key} not set")
    return value

SECRET_KEY = get_required_env("SECRET_KEY")

# SAFE: Using python-dotenv for development
from dotenv import load_dotenv
load_dotenv()  # Load .env file (add .env to .gitignore!)

# SAFE: Pydantic settings
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    api_key: str
    database_url: str
    secret_key: str

    class Config:
        env_file = ".env"

settings = Settings()
```

## Weak Password Hashing (CWE-916)

### BAD - Insecure Hashing

```python
import hashlib

# VULNERABLE: MD5 for passwords
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: SHA-256 without salt
password_hash = hashlib.sha256(password.encode()).hexdigest()

# VULNERABLE: Single iteration
password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 1)
```

### GOOD - Secure Password Hashing

```python
# SAFE: bcrypt
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# SAFE: argon2 (recommended)
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except Exception:
        return False

# SAFE: Django's make_password (uses PBKDF2 by default)
from django.contrib.auth.hashers import make_password, check_password

hashed = make_password(password)
is_valid = check_password(password, hashed)
```

## Insecure Randomness (CWE-330)

### BAD - Predictable Random Values

```python
import random

# VULNERABLE: random module for security purposes
session_id = ''.join(random.choices('abcdef0123456789', k=32))
token = random.randint(100000, 999999)
reset_code = str(random.random())
```

### GOOD - Cryptographically Secure Random

```python
import secrets

# SAFE: secrets module for security purposes
session_id = secrets.token_hex(16)  # 32 hex chars
token = secrets.token_urlsafe(32)   # URL-safe base64
reset_code = secrets.token_hex(3)   # 6 hex chars for short codes

# SAFE: Generating secure random integers
secure_int = secrets.randbelow(1000000)

# SAFE: Secure random choice
import string
alphabet = string.ascii_letters + string.digits
password = ''.join(secrets.choice(alphabet) for _ in range(16))
```

## Weak Encryption (CWE-327)

### BAD - Broken Cryptographic Algorithms

```python
from Crypto.Cipher import DES, AES

# VULNERABLE: DES (56-bit key, broken)
cipher = DES.new(key, DES.MODE_ECB)

# VULNERABLE: AES-ECB mode (patterns leak)
cipher = AES.new(key, AES.MODE_ECB)

# VULNERABLE: MD5 for integrity (collision attacks)
import hashlib
checksum = hashlib.md5(data).hexdigest()
```

### GOOD - Modern Encryption

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# SAFE: Fernet (symmetric encryption, recommended for most cases)
key = Fernet.generate_key()  # Store securely!
cipher = Fernet(key)

encrypted = cipher.encrypt(b"secret data")
decrypted = cipher.decrypt(encrypted)

# SAFE: AES-GCM for authenticated encryption
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # Never reuse nonce with same key!

encrypted = aesgcm.encrypt(nonce, plaintext, associated_data)
decrypted = aesgcm.decrypt(nonce, encrypted, associated_data)

# SAFE: SHA-256 or SHA-3 for integrity
import hashlib
checksum = hashlib.sha256(data).hexdigest()
```

## Key Management

### BAD - Poor Key Handling

```python
# VULNERABLE: Key in source code
ENCRYPTION_KEY = b"my-32-byte-key-for-encryption!!"

# VULNERABLE: Weak key derivation
key = password.encode().ljust(32, b'\0')
```

### GOOD - Proper Key Management

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# SAFE: Derive key from password with PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # OWASP recommended minimum
    )
    return kdf.derive(password.encode())

# SAFE: Generate and store salt
salt = os.urandom(16)  # Store with encrypted data

# SAFE: Load key from environment
ENCRYPTION_KEY = base64.b64decode(os.environ["ENCRYPTION_KEY"])
```

## Quick Reference

| Purpose | BAD | GOOD |
|---------|-----|------|
| Secrets storage | Hardcoded in code | `os.environ`, `.env` (gitignored) |
| Password hashing | MD5, SHA-256, unsalted | bcrypt, argon2, Django `make_password` |
| Random tokens | `random` module | `secrets.token_hex()`, `secrets.token_urlsafe()` |
| Symmetric encryption | DES, AES-ECB | Fernet, AES-GCM |
| Integrity | MD5 | SHA-256, SHA-3 |
| Key derivation | Simple padding | PBKDF2 with 600k+ iterations |
