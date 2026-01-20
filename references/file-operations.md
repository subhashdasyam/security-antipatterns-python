# File Operations Security

**CWE:** CWE-22 (Path Traversal), CWE-377 (Insecure Temp File), CWE-59 (Symlink Attack)
**OWASP:** A01:2021 Broken Access Control

## Path Traversal (CWE-22)

### BAD - Unsanitized Path Construction

```python
import os

# VULNERABLE: Direct path concatenation with user input
def get_file(filename):
    path = "/var/www/uploads/" + filename  # ../../../etc/passwd works!
    return open(path).read()

# VULNERABLE: os.path.join doesn't prevent traversal
def get_document(doc_name):
    path = os.path.join("/documents", doc_name)  # Still vulnerable!
    return open(path).read()

# VULNERABLE: String formatting
base_dir = "/uploads"
file_path = f"{base_dir}/{user_input}"
```

### GOOD - Safe Path Handling

```python
from pathlib import Path

UPLOAD_DIR = Path("/var/www/uploads").resolve()

def get_file_safe(filename: str) -> str:
    """Safely retrieve a file, preventing path traversal."""
    # Construct the full path
    requested_path = (UPLOAD_DIR / filename).resolve()

    # Verify it's still within the base directory
    if not requested_path.is_relative_to(UPLOAD_DIR):
        raise ValueError("Path traversal detected")

    # Verify it exists and is a file (not directory)
    if not requested_path.is_file():
        raise FileNotFoundError("File not found")

    return requested_path.read_text()

# SAFE: Alternative using os.path
import os

def get_file_safe_os(base_dir: str, filename: str) -> str:
    # Resolve both paths
    base = os.path.realpath(base_dir)
    full_path = os.path.realpath(os.path.join(base, filename))

    # Check that resolved path is within base
    if not full_path.startswith(base + os.sep):
        raise ValueError("Path traversal detected")

    with open(full_path) as f:
        return f.read()
```

## Insecure Temporary Files (CWE-377)

### BAD - Predictable Temp Files

```python
import os

# VULNERABLE: Predictable temp file location
temp_file = "/tmp/myapp_" + username + ".txt"
with open(temp_file, "w") as f:
    f.write(sensitive_data)

# VULNERABLE: Race condition with os.path.exists
if not os.path.exists("/tmp/output.txt"):
    with open("/tmp/output.txt", "w") as f:  # TOCTOU race!
        f.write(data)

# VULNERABLE: Not cleaning up temp files
temp = open("/tmp/processing.dat", "w")
temp.write(data)
# File persists with sensitive data
```

### GOOD - Secure Temporary Files

```python
import tempfile
import os

# SAFE: NamedTemporaryFile (auto-cleanup)
with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
    f.write(sensitive_data)
    f.flush()
    # Use f.name if you need the path
    process_file(f.name)
# File automatically deleted when context exits

# SAFE: mkstemp for more control
fd, path = tempfile.mkstemp(suffix='.txt', prefix='secure_')
try:
    with os.fdopen(fd, 'w') as f:
        f.write(sensitive_data)
    # Process the file
finally:
    os.unlink(path)  # Explicit cleanup

# SAFE: Temporary directory
with tempfile.TemporaryDirectory() as tmpdir:
    file_path = os.path.join(tmpdir, "data.txt")
    with open(file_path, 'w') as f:
        f.write(data)
    # Directory and contents auto-deleted
```

## Symlink Attacks (CWE-59)

### BAD - Following Symlinks Blindly

```python
# VULNERABLE: Follows symlinks without checking
def delete_user_file(username, filename):
    path = f"/uploads/{username}/{filename}"
    os.remove(path)  # If symlink points to /etc/passwd...

# VULNERABLE: Reading through symlink
with open(user_provided_path) as f:
    return f.read()  # Could read any file via symlink
```

### GOOD - Symlink-Safe Operations

```python
from pathlib import Path
import os

def safe_delete(base_dir: str, filename: str):
    """Delete a file, refusing to follow symlinks outside base."""
    base = Path(base_dir).resolve()
    target = base / filename

    # Check if it's a symlink
    if target.is_symlink():
        # Resolve and verify target is within base
        real_target = target.resolve()
        if not real_target.is_relative_to(base):
            raise ValueError("Symlink points outside allowed directory")

    # Final resolution check
    final_path = target.resolve()
    if not final_path.is_relative_to(base):
        raise ValueError("Path traversal detected")

    os.remove(final_path)

# SAFE: Use O_NOFOLLOW to refuse symlinks entirely
import os

def read_no_symlink(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, os.fstat(fd).st_size)
    finally:
        os.close(fd)
```

## File Permissions (CWE-732)

### BAD - Overly Permissive

```python
# VULNERABLE: World-writable file
os.chmod(config_file, 0o777)

# VULNERABLE: Default umask may be too permissive
with open("/etc/myapp/config", "w") as f:
    f.write(sensitive_config)
```

### GOOD - Restrictive Permissions

```python
import os
import stat

# SAFE: Create file with restricted permissions
def write_secure_file(path: str, content: str):
    # Set restrictive umask
    old_umask = os.umask(0o077)
    try:
        with open(path, 'w') as f:
            f.write(content)
        # Explicitly set permissions
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    finally:
        os.umask(old_umask)

# SAFE: Create directory with restricted permissions
os.makedirs(secret_dir, mode=0o700, exist_ok=True)
```

## Quick Reference

| Vulnerability | Pattern to Avoid | Secure Alternative |
|---------------|------------------|-------------------|
| Path Traversal | String concat with user input | `pathlib` + `resolve()` + `is_relative_to()` |
| Temp File Race | `/tmp/predictable_name` | `tempfile.NamedTemporaryFile()` |
| Symlink Attack | Following symlinks blindly | `O_NOFOLLOW` or resolve + verify |
| Permissions | `chmod 777` | `chmod 600` or `700` for dirs |

## Path Traversal Checklist

1. Use `pathlib.Path` for all path operations
2. Call `.resolve()` to get absolute path
3. Use `.is_relative_to(base)` to verify containment
4. Check `is_file()` or `is_dir()` as appropriate
5. Consider symlink handling explicitly
