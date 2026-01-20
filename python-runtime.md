# Python Runtime Security

**CWE:** CWE-94 (Code Injection), CWE-1333 (ReDoS)
**Python-Specific Runtime Vulnerabilities**

## eval() and exec() (CWE-94)

### BAD - Dynamic Code Execution

```python
# VULNERABLE: eval with user input
user_expr = request.GET['expression']
result = eval(user_expr)  # Attacker runs: __import__('os').system('rm -rf /')

# VULNERABLE: exec with user input
code = request.POST['code']
exec(code)  # Full arbitrary code execution!

# VULNERABLE: compile with user input
user_code = request.POST['code']
compiled = compile(user_code, '<string>', 'exec')
exec(compiled)
```

### GOOD - Safe Alternatives

```python
import ast
import operator

# SAFE: For simple math expressions, use ast.literal_eval
def safe_eval_literal(expr: str):
    """Safely evaluate literals only (strings, numbers, tuples, lists, dicts)."""
    return ast.literal_eval(expr)  # Only literals, no function calls

# SAFE: For math, build a restricted evaluator
ALLOWED_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def safe_math_eval(expr: str) -> float:
    """Evaluate simple math expressions safely."""
    tree = ast.parse(expr, mode='eval')

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError(f"Invalid constant: {node.value}")
        elif isinstance(node, ast.BinOp):
            op_type = type(node.op)
            if op_type not in ALLOWED_OPERATORS:
                raise ValueError(f"Operator not allowed: {op_type}")
            return ALLOWED_OPERATORS[op_type](_eval(node.left), _eval(node.right))
        raise ValueError(f"Invalid node type: {type(node)}")

    return _eval(tree)

# SAFE: Use dedicated libraries for specific use cases
# - sympy for symbolic math
# - numexpr for numerical expressions
# - pandas.eval for dataframe expressions (with restrictions)
```

## __import__ and importlib (CWE-94)

### BAD - Dynamic Import of User Input

```python
# VULNERABLE: User controls which module to import
module_name = request.GET['module']
module = __import__(module_name)  # Attacker imports 'os', 'subprocess', etc.

# VULNERABLE: importlib with user input
import importlib
module = importlib.import_module(user_input)
```

### GOOD - Allowlist for Dynamic Imports

```python
import importlib

ALLOWED_MODULES = {'json', 'csv', 'xml'}

def safe_import(module_name: str):
    """Import only from allowlist."""
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} not allowed")
    return importlib.import_module(module_name)
```

## ReDoS - Regular Expression Denial of Service (CWE-1333)

### BAD - Vulnerable Regex Patterns

```python
import re

# VULNERABLE: Nested quantifiers
email_pattern = r'^([a-zA-Z0-9]+)*@'  # Catastrophic backtracking!
re.match(email_pattern, malicious_input)

# VULNERABLE: Overlapping alternations with quantifiers
pattern = r'^(a+)+$'
pattern = r'^(a|a)+$'
pattern = r'^(.*a){10}'

# Test: These patterns hang on input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
```

### GOOD - Safe Regex Practices

```python
import re
from regex import regex  # Third-party regex library with timeout

# SAFE: Possessive quantifiers (in regex library, not re)
pattern = regex.compile(r'^[a-zA-Z0-9]++@', flags=regex.V1)

# SAFE: Atomic groups
pattern = regex.compile(r'^(?>[a-zA-Z0-9]+)@')

# SAFE: Set timeout (regex library)
try:
    match = regex.match(pattern, user_input, timeout=1.0)
except regex.error:
    # Handle timeout
    pass

# SAFE: Limit input length before regex
MAX_INPUT_LENGTH = 1000

def safe_regex_match(pattern: str, text: str) -> bool:
    if len(text) > MAX_INPUT_LENGTH:
        raise ValueError("Input too long")
    return bool(re.match(pattern, text))

# SAFE: Use specific patterns instead of greedy ones
# Instead of: r'.*@.*'
# Use: r'[^@]+@[^@]+'
```

## globals() and locals() Exposure

### BAD - Exposing Execution Context

```python
# VULNERABLE: Passing globals/locals to eval
result = eval(user_expr, globals(), locals())  # Access to everything!

# VULNERABLE: Template engines with full context
template.render(**globals())  # Exposes all global variables
```

### GOOD - Restricted Context

```python
# SAFE: Empty or minimal context for eval (if you must use it)
SAFE_BUILTINS = {
    'abs': abs,
    'min': min,
    'max': max,
    'sum': sum,
    'len': len,
    'range': range,
    'True': True,
    'False': False,
    'None': None,
}

def restricted_eval(expr: str, variables: dict = None):
    """Evaluate with restricted builtins."""
    safe_globals = {'__builtins__': SAFE_BUILTINS}
    safe_locals = variables or {}
    return eval(expr, safe_globals, safe_locals)

# SAFE: Pass only needed variables to templates
template.render(
    user=current_user,
    items=items,
    # Only pass what's needed
)
```

## subprocess Security

### BAD - Shell Injection via subprocess

```python
import subprocess

# VULNERABLE: shell=True with user input
subprocess.run(f"echo {user_input}", shell=True)

# VULNERABLE: String command with shell=True
subprocess.Popen(f"ls {directory}", shell=True)

# VULNERABLE: Array with shell=True (still concatenated)
subprocess.run(["ls", directory], shell=True)  # shell=True makes this unsafe
```

### GOOD - Safe subprocess Usage

```python
import subprocess
import shlex

# SAFE: List arguments without shell
subprocess.run(["echo", user_input], shell=False, check=True)

# SAFE: Capture output safely
result = subprocess.run(
    ["ls", "-la", directory],
    shell=False,
    capture_output=True,
    text=True,
    check=True,
    timeout=30,
)

# SAFE: If shell is absolutely required, use shlex.quote
# (But prefer avoiding shell=True entirely)
subprocess.run(
    f"grep {shlex.quote(pattern)} {shlex.quote(filename)}",
    shell=True,
)

# SAFE: Use Python libraries instead of shell commands
from pathlib import Path
files = list(Path(directory).iterdir())  # Instead of subprocess ls
```

## getattr/setattr with User Input

### BAD - Attribute Access with User Input

```python
# VULNERABLE: Arbitrary attribute access
attr_name = request.GET['attr']
value = getattr(obj, attr_name)  # Could access __class__, __dict__, etc.

# VULNERABLE: Setting arbitrary attributes
setattr(obj, user_key, user_value)
```

### GOOD - Allowlist Attribute Access

```python
ALLOWED_ATTRS = {'name', 'email', 'bio'}

def safe_getattr(obj, attr_name: str):
    """Get attribute only from allowlist."""
    if attr_name not in ALLOWED_ATTRS:
        raise ValueError(f"Attribute {attr_name} not allowed")
    return getattr(obj, attr_name)

def safe_setattr(obj, attr_name: str, value):
    """Set attribute only from allowlist."""
    if attr_name not in ALLOWED_ATTRS:
        raise ValueError(f"Attribute {attr_name} not allowed")
    setattr(obj, attr_name, value)
```

## Quick Reference

| Vulnerability | Pattern to Avoid | Secure Alternative |
|---------------|------------------|-------------------|
| Code Injection | `eval(user_input)` | `ast.literal_eval`, custom parser |
| Dynamic Import | `__import__(user_input)` | Allowlist of modules |
| ReDoS | Nested quantifiers `(a+)+` | Possessive quantifiers, timeout, input limit |
| Context Exposure | `eval(..., globals())` | Restricted builtins dict |
| Command Injection | `shell=True` | `subprocess.run([...], shell=False)` |
| Attribute Injection | `getattr(obj, user_input)` | Allowlist of attributes |

## Detection Tools

```bash
# Bandit detects many of these
bandit -r . -t B102,B307,B506

# B102: exec used
# B307: eval used
# B506: yaml.load

# semgrep rules for Python security
semgrep --config p/python
```
