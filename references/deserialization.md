# Unsafe Deserialization

**CWE:** CWE-502 (Deserialization of Untrusted Data)
**OWASP:** A08:2021 Software and Data Integrity Failures

## Overview

Python's serialization libraries can execute arbitrary code during deserialization. This is one of Python's most critical security issues.

**CRITICAL:** Never deserialize untrusted data with pickle, yaml.load, marshal, or shelve.

## pickle - Remote Code Execution (CWE-502)

### BAD - Deserializing Untrusted Data

```python
import pickle

# VULNERABLE: pickle.loads on user data (IMMEDIATE RCE)
user_data = request.body
obj = pickle.loads(user_data)  # Attacker executes arbitrary code!

# VULNERABLE: pickle.load from untrusted file
with open(user_uploaded_file, "rb") as f:
    obj = pickle.load(f)

# VULNERABLE: Loading pickled data from Redis/cache without verification
cached = redis_client.get(key)
obj = pickle.loads(cached)  # If attacker can write to cache = RCE
```

### GOOD - Safe Alternatives

```python
import json
import hmac
import hashlib

# SAFE: Use JSON for untrusted data
user_data = request.body
obj = json.loads(user_data)

# SAFE: If pickle required for internal use, sign it
def sign_data(data: bytes, secret: bytes) -> bytes:
    signature = hmac.new(secret, data, hashlib.sha256).digest()
    return signature + data

def verify_and_load(signed_data: bytes, secret: bytes):
    signature, data = signed_data[:32], signed_data[32:]
    expected = hmac.new(secret, data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature")
    return pickle.loads(data)  # Only after signature verification

# SAFE: Use msgpack for binary serialization
import msgpack
obj = msgpack.unpackb(user_data, raw=False)
```

## yaml.load - Code Execution (CWE-502)

### BAD - Unsafe YAML Loading

```python
import yaml

# VULNERABLE: yaml.load without Loader (Python < 3.9 default is unsafe)
config = yaml.load(user_input)  # RCE possible!

# VULNERABLE: yaml.load with FullLoader still allows some attacks
config = yaml.load(user_input, Loader=yaml.FullLoader)

# VULNERABLE: yaml.unsafe_load
config = yaml.unsafe_load(user_input)
```

### GOOD - Safe YAML Loading

```python
import yaml

# SAFE: Always use safe_load
config = yaml.safe_load(user_input)

# SAFE: SafeLoader explicitly
config = yaml.load(user_input, Loader=yaml.SafeLoader)

# SAFE: For complex objects, use JSON or define custom constructors
import json
config = json.loads(user_input)
```

## marshal - Never Use with Untrusted Data

### BAD - marshal with External Data

```python
import marshal

# VULNERABLE: marshal.loads on untrusted data
code = marshal.loads(user_bytes)  # Can create malicious code objects
```

### GOOD - Avoid marshal for User Data

```python
# SAFE: marshal should ONLY be used for internal .pyc files
# For user data, use JSON or msgpack
import json
data = json.loads(user_input)
```

## jsonpickle - Also Dangerous

### BAD - jsonpickle Deserialization

```python
import jsonpickle

# VULNERABLE: jsonpickle.decode on untrusted data
obj = jsonpickle.decode(user_json)  # Can instantiate arbitrary classes
```

### GOOD - JSON with Schema Validation

```python
from pydantic import BaseModel
import json

class UserData(BaseModel):
    name: str
    email: str

# SAFE: Parse JSON, validate with Pydantic
raw = json.loads(user_input)
user = UserData(**raw)
```

## shelve - Pickle-Based Storage

### BAD - shelve with Untrusted Data

```python
import shelve

# VULNERABLE: shelve uses pickle internally
db = shelve.open(user_provided_path)  # If attacker controls file = RCE
```

### GOOD - Use SQLite or JSON Storage

```python
import sqlite3
import json

# SAFE: SQLite for structured storage
conn = sqlite3.connect("data.db")

# SAFE: JSON files for simple storage
with open("config.json") as f:
    config = json.load(f)
```

## Quick Reference

| Library | Risk Level | Secure Alternative |
|---------|------------|-------------------|
| `pickle.loads()` | CRITICAL - RCE | JSON, msgpack, signed pickle |
| `yaml.load()` | CRITICAL - RCE | `yaml.safe_load()` |
| `marshal.loads()` | CRITICAL - RCE | JSON (never use marshal for user data) |
| `jsonpickle.decode()` | HIGH - Arbitrary class instantiation | JSON + Pydantic validation |
| `shelve.open()` | CRITICAL - RCE (uses pickle) | SQLite, JSON files |

## Detection

```bash
# Bandit will flag these
bandit -r . -t B301,B302,B303,B506
# B301: pickle
# B302: marshal
# B303: md5/sha1 (related)
# B506: yaml_load
```
