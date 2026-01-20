# Input Validation

**CWE:** CWE-20 (Improper Input Validation), CWE-434 (Unrestricted Upload), CWE-915 (Mass Assignment)
**OWASP:** A03:2021 Injection, API3:2023 Broken Object Property Level Authorization

## Missing Validation (CWE-20)

### BAD - Trusting User Input

```python
# VULNERABLE: Direct use of request data
@app.post("/api/users")
def create_user(request):
    user = User(
        name=request.json["name"],
        email=request.json["email"],
        age=request.json["age"],  # Could be negative, string, etc.
    )
    user.save()

# VULNERABLE: No type checking
def process_order(quantity):
    total = quantity * 10  # What if quantity is "10; DROP TABLE orders"?
```

### GOOD - Validate with Pydantic

```python
from pydantic import BaseModel, EmailStr, Field, field_validator

class CreateUserRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    age: int = Field(ge=0, le=150)

    @field_validator('name')
    @classmethod
    def name_must_be_alphanumeric(cls, v):
        if not v.replace(' ', '').isalnum():
            raise ValueError('Name must be alphanumeric')
        return v.strip()

# SAFE: FastAPI with Pydantic validation
@app.post("/api/users")
def create_user(user_data: CreateUserRequest):
    user = User(**user_data.model_dump())
    user.save()
```

### GOOD - Django Forms Validation

```python
from django import forms
from django.core.validators import MinLengthValidator

class UserForm(forms.Form):
    name = forms.CharField(
        max_length=100,
        validators=[MinLengthValidator(1)]
    )
    email = forms.EmailField()
    age = forms.IntegerField(min_value=0, max_value=150)

# SAFE: Validate in view
def create_user(request):
    form = UserForm(request.POST)
    if form.is_valid():
        user = User.objects.create(**form.cleaned_data)
```

## Mass Assignment (CWE-915)

### BAD - Accepting All Fields

```python
# VULNERABLE: User can set any field including is_admin
@app.put("/api/users/{user_id}")
def update_user(user_id: int, request):
    user = User.objects.get(id=user_id)
    for key, value in request.json.items():
        setattr(user, key, value)  # Attacker sets is_admin=True!
    user.save()

# VULNERABLE: Django update with unfiltered data
User.objects.filter(id=user_id).update(**request.POST)

# VULNERABLE: Unpacking dict into model
user = User(**request.json)  # All fields accepted!
```

### GOOD - Explicit Field Allowlist

```python
from pydantic import BaseModel

# SAFE: Only allow specific fields
class UpdateUserRequest(BaseModel):
    name: str | None = None
    email: str | None = None
    # is_admin intentionally excluded

@app.put("/api/users/{user_id}")
def update_user(user_id: int, data: UpdateUserRequest):
    user = User.objects.get(id=user_id)
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)
    user.save()

# SAFE: Django with explicit fields
ALLOWED_UPDATE_FIELDS = {'name', 'email', 'bio'}
update_data = {k: v for k, v in request.POST.items() if k in ALLOWED_UPDATE_FIELDS}
User.objects.filter(id=user_id).update(**update_data)
```

## Unrestricted File Upload (CWE-434)

### BAD - No File Validation

```python
# VULNERABLE: Accept any file
@app.post("/upload")
def upload_file(file: UploadFile):
    with open(f"uploads/{file.filename}", "wb") as f:
        f.write(file.file.read())  # Path traversal + any file type!

# VULNERABLE: Only checking extension (easily spoofed)
if file.filename.endswith('.jpg'):
    save_file(file)  # Could be malicious.jpg.php
```

### GOOD - Comprehensive File Validation

```python
import magic
import os
from pathlib import Path
import uuid

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif'}
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_upload(file: UploadFile) -> bool:
    # Check extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension {ext} not allowed")

    # Check file size
    file.file.seek(0, 2)  # Seek to end
    size = file.file.tell()
    file.file.seek(0)  # Reset
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large")

    # Check MIME type via magic bytes
    header = file.file.read(2048)
    file.file.seek(0)
    mime = magic.from_buffer(header, mime=True)
    if mime not in ALLOWED_MIMES:
        raise ValueError(f"MIME type {mime} not allowed")

    return True

@app.post("/upload")
def upload_file(file: UploadFile):
    validate_upload(file)

    # Generate safe filename
    ext = Path(file.filename).suffix.lower()
    safe_filename = f"{uuid.uuid4()}{ext}"

    # Store outside webroot or use object storage
    upload_path = Path("/secure/uploads") / safe_filename
    with open(upload_path, "wb") as f:
        f.write(file.file.read())

    return {"filename": safe_filename}
```

## Type Coercion Issues

### BAD - Relying on Loose Type Checking

```python
# VULNERABLE: isinstance can be fooled with subclasses
def is_safe_query(query):
    if isinstance(query, str):
        return True  # Subclasses of str pass!

# VULNERABLE: Truthy/falsy checks
def process(data):
    if data:  # Empty dict {} is falsy but valid
        return data["value"]
```

### GOOD - Strict Validation

```python
from pydantic import BaseModel, ConfigDict

class StrictInput(BaseModel):
    model_config = ConfigDict(strict=True)  # No type coercion

    value: int  # "123" will fail, must be actual int
    name: str

# SAFE: Explicit type checking
def process(data):
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
    if "value" not in data:
        raise ValueError("Missing required field: value")
```

## Quick Reference

| Vulnerability | Pattern to Avoid | Secure Alternative |
|---------------|------------------|-------------------|
| Missing validation | Direct `request.json` use | Pydantic models, Django Forms |
| Mass assignment | `Model(**request.data)` | Explicit field allowlist |
| File upload | Trust filename/extension | UUID names + magic bytes + size limit |
| Type confusion | Loose `isinstance` | Pydantic strict mode |
