# CODEGUARD SKILL
# Expert-Level Code Validation, Safety & Correctness Enforcement
# Languages: Python | Java | JavaScript/TypeScript | Kotlin
# Environments: Local | Docker | CI/CD (GitHub Actions, Jenkins)

---

## OVERVIEW

CodeGuard is a senior-engineer-grade validation skill that wraps any LLM code
generation pipeline. It enforces correctness, security, performance, and edge-case
coverage before code ever reaches a human reviewer or production environment.

**Philosophy:**
  Generate → Validate → Score → Flag → Suggest Fix → Human Decision

The model NEVER self-approves output. Every generated artifact passes through
all four validation layers before being surfaced. Failures are reported with
severity, location, and a concrete fix suggestion — never just a raw error message.

---

## ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LLM CODE GENERATION                          │
│           (Llama / Mistral / DeepSeek / GPT / Claude / etc.)        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  raw generated code
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     LAYER 0 — AST PARSE GATE                        │
│  Reject unparseable code immediately. No further analysis on syntax  │
│  failures — return parse error with line number to LLM for retry.   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  syntactically valid AST
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  LAYER 1 — STATIC ANALYSIS                          │
│  • Type checking (mypy / tsc / javac --Xlint / ktlint)              │
│  • Linting (ruff / eslint / checkstyle / detekt)                    │
│  • Complexity scoring (radon / plato / lizard)                      │
│  • Dead code detection                                               │
│  • Null/None safety analysis                                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  static-clean code
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  LAYER 2 — SECURITY SCAN                            │
│  • SAST: bandit (Py) / semgrep (all) / spotbugs (Java) / njsscan   │
│  • Secret detection: trufflehog / detect-secrets                    │
│  • Dependency CVE check: safety (Py) / npm audit / OWASP depcheck   │
│  • OWASP Top 10 pattern matching                                    │
│  • SQL injection, XSS, path traversal, command injection patterns   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  security-clean code
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 3 — DYNAMIC TEST GENERATION & EXECUTION          │
│  • Property-based fuzzing: Hypothesis (Py) / fast-check (JS)        │
│  • Edge case matrix: null, empty, max, min, negative, unicode, NaN  │
│  • Boundary value analysis on all numeric parameters                │
│  • Mutation testing: mutmut (Py) / stryker (JS/TS)                 │
│  • Concurrency stress test: threading.Barrier / Promise.all storms  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  dynamically verified code
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 4 — MEMORY & PERFORMANCE PROFILING               │
│  • Memory: tracemalloc (Py) / heapdump (JS) / jmap (Java)          │
│  • Leak detection: objgraph (Py) / valgrind patterns                │
│  • Time complexity estimation via AST loop nesting depth            │
│  • Algorithmic anti-patterns: N+1, nested loops on large N          │
│  • Async correctness: unawaited coroutines, blocking calls in async │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  profiled code
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SCORECARD & HUMAN REPORT                         │
│  • Per-finding: severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)           │
│  • Location: file, line, column                                     │
│  • Rule violated: with documentation link                           │
│  • Concrete fix suggestion (not just error message)                 │
│  • Overall PASS / CONDITIONAL / FAIL verdict                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## WHEN TO USE THIS SKILL

Claude MUST invoke this skill whenever:
- Writing any function longer than 10 lines
- Writing any code that touches: IO, network, database, auth, crypto
- Writing any concurrent / async code
- Writing any code that processes user input
- Writing recursive functions
- Generating code in Java or Kotlin (null safety is harder)
- Writing any loop over collections or data structures
- Generating configuration files (YAML, JSON, env files)

Claude SHOULD NOT invoke this skill for:
- Single-line utility snippets with no side effects
- Pure string formatting with no logic
- Comment-only changes

---

## LAYER 0 — AST PARSE GATE

### Behavior
Attempt to parse generated code into an AST before any other check.
If parse fails: immediately return parse error, line number, and retry signal.

### Tools by Language
```
Python:       ast.parse(code)  — stdlib, zero deps
JavaScript:   @babel/parser or acorn
TypeScript:   typescript compiler API (tsc --noEmit)
Java:         javac -proc:none (compile check only)
Kotlin:       kotlinc -script or detekt parse phase
```

### Failure Response Template
```
[LAYER 0 — PARSE FAILURE]
Language:    Python
Line:        14, Column: 8
Error:       SyntaxError: invalid syntax — unexpected token '}'
Likely cause: Missing closing parenthesis on line 13
Suggested fix: Add ')' at end of line 13 before the closing brace
Action:      REGENERATE — do not proceed to further validation
```

---

## LAYER 1 — STATIC ANALYSIS

### 1A. Type Safety

**Python — mypy (strict mode)**
```bash
mypy --strict \
     --disallow-untyped-defs \
     --disallow-any-generics \
     --warn-return-any \
     --no-implicit-optional \
     --check-untyped-defs \
     generated_code.py
```
Critical checks:
- All function parameters must have type annotations
- Return types must be declared
- Optional[T] must be used, never bare None assignment
- No `Any` type unless explicitly justified

**JavaScript/TypeScript — tsc + ESLint**
```bash
tsc --strict --noImplicitAny --strictNullChecks --noImplicitReturns \
    --noFallthroughCasesInSwitch --noUnusedLocals --noUnusedParameters \
    --target ES2022 generated_code.ts
```

**Java — javac + SpotBugs**
```bash
javac -Xlint:all -Werror GeneratedCode.java
# Follow with:
spotbugs -textui -effort:max -high GeneratedCode.class
```

**Kotlin — ktlint + detekt**
```bash
ktlint --reporter=json generated_code.kt
detekt --input generated_code.kt --config detekt.yml
```

### 1B. Linting Rules (Non-Negotiable)

**Python — ruff (replaces flake8 + isort + pylint)**
```bash
ruff check --select ALL \
           --ignore ANN101,ANN102,D100,D104 \
           generated_code.py
```
Must-enforce rules:
- E501: max line length 100
- F401: no unused imports
- F841: no unused variables
- B006: no mutable default arguments ← LLM common failure
- B007: loop variable not used in loop body
- B023: loop variable captured by closure ← LLM common failure
- S: all bandit security rules via ruff-bandit
- RUF: all ruff-specific rules

**ESLint (JS/TS)**
```json
{
  "rules": {
    "no-var": "error",
    "prefer-const": "error",
    "no-floating-decimal": "error",
    "eqeqeq": ["error", "always"],
    "@typescript-eslint/no-floating-promises": "error",
    "@typescript-eslint/await-thenable": "error",
    "no-implicit-coercion": "error",
    "no-prototype-builtins": "error",
    "security/detect-sql-injection": "error",
    "security/detect-non-literal-regexp": "error"
  }
}
```

### 1C. Complexity Scoring

Cyclomatic complexity threshold: **≤ 10 per function** (warn), **≤ 15** (error).
Cognitive complexity threshold: **≤ 15 per function** (warn), **≤ 20** (error).

```bash
# Python
radon cc generated_code.py -s -n B   # flag B and above (score > 5)
radon mi generated_code.py -s        # maintainability index

# JavaScript
plato -r -d report generated_code.js

# All languages
lizard generated_code.py --CCN 10 --length 50 --arguments 5
```

If complexity exceeds threshold:
```
[LAYER 1 — COMPLEXITY VIOLATION]
Function:    process_user_data() at line 42
CC Score:    17 (threshold: 10)
Suggestion:  Extract the inner loop (lines 58–72) into a separate
             validate_record() function. The retry logic (lines 74–89)
             should become a with_retry() decorator.
```

### 1D. Null / None Safety Patterns

LLM-generated code must pass these AST-level checks before proceeding:

```python
# CODEGUARD NULL SAFETY CHECKS (Python AST)

BANNED_PATTERNS = [
    # Pattern: dict access without .get()
    # Detects: d["key"] where d might be None or key might be absent
    "direct_dict_subscript_on_optional",

    # Pattern: chained attribute access without guards
    # Detects: a.b.c.d where any link could be None
    "unguarded_attribute_chain_depth_gt_2",

    # Pattern: return value of functions like .find(), .get() used without None check
    "unchecked_nullable_return_use",

    # Pattern: list index access without bounds check
    "unchecked_list_subscript",
]
```

---

## LAYER 2 — SECURITY SCAN

### 2A. SAST (Static Application Security Testing)

**Primary — Semgrep (all languages)**
```bash
semgrep --config=auto \
        --config=p/owasp-top-ten \
        --config=p/secrets \
        --config=p/sql-injection \
        --config=p/xss \
        --config=p/command-injection \
        --config=p/path-traversal \
        --config=p/insecure-transport \
        --json \
        generated_code/
```

**Python-specific — Bandit**
```bash
bandit -r generated_code/ \
       -l -ii \
       -f json \
       --skip B101   # allow assert in tests only
```

Critical bandit rules:
- B102: use of exec
- B105/B106/B107: hardcoded passwords
- B201: flask debug=True
- B301: pickle usage (deserialization risk)
- B324: use of weak hash (md5/sha1)
- B501-B509: SSL/TLS misconfigurations
- B601-B608: shell injection, SQL injection

**Java — SpotBugs + FindSecBugs**
```bash
spotbugs -textui \
         -pluginList findsecbugs-plugin.jar \
         -effort:max \
         -high \
         generated_classes/
```

**JavaScript/TypeScript — njsscan**
```bash
njsscan --json generated_code/
```

### 2B. Secret Detection

```bash
# TruffleHog — entropy-based + regex
trufflehog filesystem ./generated_code/ --json

# detect-secrets
detect-secrets scan generated_code/ --all-files
```

Zero-tolerance secrets list:
- API keys (any provider)
- Passwords in any form
- Private keys (RSA, EC, JWT secrets)
- Database connection strings with credentials
- AWS/GCP/Azure credentials
- OAuth client secrets

If ANY secret detected: **CRITICAL — HARD BLOCK, do not surface code to user.**

### 2C. OWASP Top 10 Pattern Rules

```
A01 — Broken Access Control:
  Flag: admin checks that use string equality instead of role enum
  Flag: hardcoded user IDs or role names in conditionals
  Flag: missing authorization on any endpoint handler

A02 — Cryptographic Failures:
  Flag: MD5, SHA1, DES, RC4 usage
  Flag: random.random() for security purposes (use secrets module)
  Flag: ECB mode in any cipher
  Flag: hardcoded IV/salt values

A03 — Injection:
  Flag: any string concatenation into SQL, shell commands, XML, LDAP
  Flag: eval(), exec(), os.system() with non-literal arguments
  Flag: innerHTML assignment (JS)
  Flag: unparameterized database queries (ANY language)

A04 — Insecure Design:
  Flag: no rate limiting on auth endpoints
  Flag: no input length limits on user-supplied strings
  Flag: unbounded resource allocation (while True without exit condition)

A05 — Security Misconfiguration:
  Flag: debug=True in any config
  Flag: CORS allow-origin: * in non-public APIs
  Flag: default credentials (admin/admin, root/root)
  Flag: stack traces exposed in HTTP responses

A07 — Auth Failures:
  Flag: == comparison for token/password checks (timing attack)
  Flag: tokens stored in localStorage (JS) — use httpOnly cookies
  Flag: JWT without signature verification (decode without verify=True)
  Flag: no expiry on sessions or tokens

A08 — Software & Data Integrity:
  Flag: pickle.loads() on user-supplied data
  Flag: yaml.load() without Loader= (use yaml.safe_load())
  Flag: deserialization of untrusted JSON into live objects

A10 — Server-Side Request Forgery:
  Flag: HTTP requests to URLs constructed from user input without allowlist
```

### 2D. Dependency CVE Check

```bash
# Python
pip-audit --requirement requirements.txt --format json

# JavaScript/TypeScript
npm audit --json

# Java
dependency-check --project "generated" --scan ./pom.xml --format JSON

# Kotlin
./gradlew dependencyCheckAnalyze
```

Threshold: CRITICAL or HIGH CVEs → **HARD BLOCK**
MEDIUM CVEs → **FLAG with upgrade suggestion**

---

## LAYER 3 — DYNAMIC TEST GENERATION & EXECUTION

### 3A. Edge Case Matrix (Applied to Every Function)

For each generated function, CodeGuard auto-generates tests for:

```
NUMERIC PARAMETERS:
  ✓ Zero (0)
  ✓ Negative (-1, INT_MIN)
  ✓ Maximum (INT_MAX, FLOAT_MAX)
  ✓ NaN (float('nan'))
  ✓ Infinity (float('inf'), -float('inf'))
  ✓ Very small float (1e-308)
  ✓ Off-by-one from boundaries

STRING PARAMETERS:
  ✓ Empty string ""
  ✓ Single character
  ✓ Unicode / emoji (u"\U0001F600")
  ✓ Null bytes ("\x00")
  ✓ Maximum length + 1
  ✓ SQL injection probe ("'; DROP TABLE--")
  ✓ XSS probe ("<script>alert(1)</script>")
  ✓ Path traversal ("../../etc/passwd")
  ✓ Whitespace only ("   \t\n")
  ✓ Very long string (10,000 chars)

COLLECTION PARAMETERS (list, array, map):
  ✓ Empty collection []
  ✓ Single element
  ✓ Duplicate elements
  ✓ None/null elements inside collection
  ✓ Nested collections
  ✓ Very large collection (100,000 elements)
  ✓ Reverse-sorted input (for sort-dependent code)
  ✓ Already-sorted input

OBJECT/CLASS PARAMETERS:
  ✓ null / None
  ✓ Partially initialized (missing optional fields)
  ✓ All fields at boundary values simultaneously

BOOLEAN PARAMETERS:
  ✓ True, False — both paths must be exercised

ASYNC / CONCURRENT:
  ✓ Concurrent calls (10, 100, 1000 simultaneous)
  ✓ Timeout simulation
  ✓ Partial failure (some calls succeed, some fail)
```

### 3B. Property-Based Fuzzing

**Python — Hypothesis**
```python
# Auto-generated fuzz harness for any function
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st
import generated_module

@given(
    x=st.one_of(
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.binary(),
        st.none(),
        st.lists(st.integers()),
        st.dictionaries(st.text(), st.integers()),
    )
)
@settings(
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
    deriving_from_ancestors=True,
)
def test_function_never_crashes(x):
    try:
        generated_module.target_function(x)
    except (TypeError, ValueError):
        pass   # expected for invalid input types
    except Exception as e:
        raise AssertionError(
            f"Unexpected exception for input {x!r}: {type(e).__name__}: {e}"
        )
```

**JavaScript/TypeScript — fast-check**
```typescript
import * as fc from 'fast-check';
import { targetFunction } from './generated';

describe('Property-based fuzz', () => {
  it('never throws unexpected errors', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.integer(), fc.double({ noNaN: false }), fc.string(),
          fc.array(fc.integer()), fc.object(), fc.constant(null),
          fc.constant(undefined)
        ),
        (input) => {
          try {
            targetFunction(input);
          } catch (e) {
            if (e instanceof TypeError || e instanceof RangeError) return;
            throw e;
          }
        }
      ),
      { numRuns: 500 }
    );
  });
});
```

### 3C. Mutation Testing

Mutation testing verifies your test suite is strong enough to catch bugs.
If mutants survive, the test suite has gaps.

**Python — mutmut**
```bash
mutmut run --paths-to-mutate=generated_code.py \
           --tests-dir=tests/ \
           --runner="python -m pytest"

mutmut results   # show surviving mutants
mutmut show <id> # show what mutation survived
```

Minimum mutation kill rate: **≥ 80%**
Below 80%: report surviving mutants as untested edge cases.

**JavaScript/TypeScript — Stryker**
```json
{
  "mutate": ["src/generated/**/*.ts"],
  "testRunner": "jest",
  "reporters": ["json", "clear-text"],
  "thresholds": { "high": 80, "low": 60, "break": 50 }
}
```

### 3D. Concurrency Stress Test

For any async, threaded, or parallel code:

```python
# Python — threading stress harness
import threading
import time
from collections import Counter

def stress_test_concurrent(fn, args_list, n_threads=50, n_rounds=10):
    """
    Calls fn concurrently from n_threads threads, n_rounds times each.
    Detects: race conditions, deadlocks, corrupted shared state.
    """
    results = []
    errors  = []
    lock    = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(args):
        barrier.wait()   # all threads start simultaneously
        for _ in range(n_rounds):
            try:
                result = fn(*args)
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    errors.append((type(e).__name__, str(e)))

    threads = [threading.Thread(target=worker, args=(args,))
               for args in args_list[:n_threads]]
    [t.start() for t in threads]
    [t.join(timeout=10) for t in threads]   # 10s timeout per thread

    # Check for deadlock (threads still alive after timeout)
    alive = [t for t in threads if t.is_alive()]
    if alive:
        return {"status": "DEADLOCK", "alive_threads": len(alive)}

    return {
        "status": "PASS" if not errors else "FAIL",
        "total_calls": len(results) + len(errors),
        "errors": Counter(e[0] for e in errors),
        "error_samples": errors[:5],
    }
```

---

## LAYER 4 — MEMORY & PERFORMANCE PROFILING

### 4A. Memory Profiling

**Python — tracemalloc + memory_profiler**
```python
import tracemalloc
import gc

def profile_memory(fn, *args, **kwargs):
    gc.collect()
    tracemalloc.start()

    result = fn(*args, **kwargs)

    snapshot = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot.statistics('lineno')
    top_allocations = stats[:10]

    total_mb = sum(s.size for s in stats) / 1024 / 1024

    report = {
        "total_memory_mb": round(total_mb, 3),
        "top_allocations": [
            {
                "file": str(s.traceback[0].filename),
                "line": s.traceback[0].lineno,
                "size_kb": round(s.size / 1024, 2),
                "count": s.count,
            }
            for s in top_allocations
        ]
    }

    # Thresholds
    if total_mb > 100:
        report["verdict"] = "FAIL — exceeds 100MB threshold"
    elif total_mb > 50:
        report["verdict"] = "WARN — exceeds 50MB threshold"
    else:
        report["verdict"] = "PASS"

    return report
```

**JavaScript/Node — --expose-gc + heapUsed**
```javascript
async function profileMemory(fn, ...args) {
    if (global.gc) global.gc();
    const before = process.memoryUsage();

    await fn(...args);

    if (global.gc) global.gc();
    const after = process.memoryUsage();

    const deltaMB = (after.heapUsed - before.heapUsed) / 1024 / 1024;
    return {
        heapDeltaMB: deltaMB.toFixed(2),
        verdict: deltaMB > 100 ? "FAIL" : deltaMB > 50 ? "WARN" : "PASS"
    };
}
// Run with: node --expose-gc profiler.js
```

### 4B. Time Complexity Estimation (AST-based)

CodeGuard statically estimates time complexity by analyzing loop nesting depth
and recursive call patterns in the AST:

```python
import ast

def estimate_complexity(source: str) -> dict:
    """
    Heuristic time complexity from AST loop nesting depth.
    Not a proof — a red flag detector.
    """
    tree = ast.parse(source)
    results = []

    class LoopVisitor(ast.NodeVisitor):
        def __init__(self):
            self.depth = 0
            self.max_depth = 0
            self.function_name = "module"

        def visit_FunctionDef(self, node):
            old = self.function_name
            self.function_name = node.name
            self.generic_visit(node)
            self.function_name = old

        def visit_For(self, node):
            self.depth += 1
            self.max_depth = max(self.max_depth, self.depth)
            results.append({
                "function": self.function_name,
                "nesting_depth": self.depth,
                "line": node.lineno,
                "estimated_complexity": f"O(n^{self.depth})"
                    if self.depth > 1 else "O(n)",
                "verdict": "FAIL" if self.depth >= 3 else
                           "WARN" if self.depth == 2 else "PASS"
            })
            self.generic_visit(node)
            self.depth -= 1

        visit_While = visit_For   # same logic for while loops

    LoopVisitor().visit(tree)
    return results
```

Thresholds:
- O(n)     → PASS
- O(n²)    → WARN if n could be large (flag with message)
- O(n³)+   → FAIL — require explicit justification

### 4C. Algorithmic Anti-Pattern Detection

```
ANTI-PATTERN CHECKERS (AST + regex hybrid):

[AP-01] N+1 QUERY
  Pattern: ORM call inside a for loop
  Signals: .objects.get() / .filter() / session.query() inside for/while
  Severity: HIGH
  Fix hint: Use select_related() / prefetch_related() / JOIN

[AP-02] UNBOUNDED GROWTH
  Pattern: list.append() inside loop with no size limit
  Signals: collection grows without max_size check
  Severity: MEDIUM
  Fix hint: Add maxlen=N to deque, or preallocate with known size

[AP-03] REPEATED RECOMPUTATION
  Pattern: same expensive call inside a loop
  Signals: function call with identical arguments repeated in loop body
  Severity: MEDIUM
  Fix hint: Hoist computation above the loop, cache with @lru_cache

[AP-04] STRING CONCATENATION IN LOOP
  Pattern: str += x inside for loop (O(n²) due to immutability)
  Signals: += on string variable inside loop body
  Severity: HIGH (Python, Java)
  Fix hint: Collect in list, join at end: ''.join(parts)

[AP-05] BLOCKING CALL IN ASYNC CONTEXT
  Pattern: time.sleep() / requests.get() inside async def without await
  Signals: synchronous IO in coroutine
  Severity: CRITICAL
  Fix hint: Use asyncio.sleep() / aiohttp.get() / httpx.AsyncClient

[AP-06] INEFFICIENT MEMBERSHIP TEST
  Pattern: x in list where list is large and reused
  Signals: 'in' operator on list/tuple variable in hot path
  Severity: MEDIUM
  Fix hint: Convert to set() for O(1) lookup

[AP-07] MUTABLE DEFAULT ARGUMENT
  Pattern: def fn(x=[]) / def fn(x={})
  Signals: list/dict literal as default parameter
  Severity: HIGH (Python)
  Fix hint: Use None sentinel, create inside function body

[AP-08] REGEX IN LOOP WITHOUT PRE-COMPILE
  Pattern: re.match/search/compile called inside loop
  Signals: re.* call with literal string inside for/while
  Severity: MEDIUM
  Fix hint: Compile outside loop: pattern = re.compile(...)

[AP-09] GLOBAL INTERPRETER LOCK MISUSE (Python)
  Pattern: CPU-bound work in threading.Thread
  Signals: heavy computation in thread (not IO)
  Severity: MEDIUM
  Fix hint: Use multiprocessing.Pool for CPU-bound, threading for IO-bound

[AP-10] FLOAT EQUALITY COMPARISON
  Pattern: x == 0.0 or x == 1.0 for float values
  Signals: == operator with float literal
  Severity: HIGH
  Fix hint: Use math.isclose(x, 0.0, abs_tol=1e-9)
```

### 4D. Async Correctness Checks

```python
# Checks applied to all async code

ASYNC_CHECKS = {
    "UNAWAITED_COROUTINE": {
        "pattern": "function call to async fn without await prefix",
        "severity": "CRITICAL",
        "fix": "Add 'await' before the coroutine call"
    },
    "BLOCKING_IN_ASYNC": {
        "pattern": "time.sleep / requests.get / open() in async def",
        "severity": "CRITICAL",
        "fix": "Replace with asyncio.sleep / aiohttp / aiofiles"
    },
    "MISSING_LOCK_ON_SHARED_STATE": {
        "pattern": "read-modify-write on shared var across await point",
        "severity": "HIGH",
        "fix": "Wrap critical section in async with asyncio.Lock()"
    },
    "UNHANDLED_TASK_EXCEPTION": {
        "pattern": "asyncio.create_task without .add_done_callback",
        "severity": "HIGH",
        "fix": "Add error handler: task.add_done_callback(handle_error)"
    },
    "NESTED_EVENT_LOOP": {
        "pattern": "asyncio.run() inside async def",
        "severity": "CRITICAL",
        "fix": "Never nest asyncio.run(). Use await directly."
    }
}
```

---

## SCORECARD FORMAT

Every validation run produces a structured JSON scorecard:

```json
{
  "run_id": "cg-20250222-001",
  "timestamp": "2025-02-22T13:00:00Z",
  "language": "python",
  "file": "generated_code.py",
  "verdict": "CONDITIONAL",

  "summary": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 4,
    "total_issues": 10
  },

  "layer_results": {
    "L0_parse":       "PASS",
    "L1_static":      "WARN",
    "L2_security":    "PASS",
    "L3_dynamic":     "WARN",
    "L4_performance": "PASS"
  },

  "findings": [
    {
      "id": "CG-H001",
      "layer": "L1_static",
      "severity": "HIGH",
      "rule": "B006 — mutable-default-argument",
      "location": { "file": "generated_code.py", "line": 34, "col": 14 },
      "message": "Default argument is a mutable list. All callers share this object.",
      "code_snippet": "def process(items=[]):",
      "fix_suggestion": "Use 'def process(items=None)' and inside the body: 'if items is None: items = []'",
      "docs": "https://docs.python-guide.org/writing/gotchas/#mutable-default-arguments"
    },
    {
      "id": "CG-H002",
      "layer": "L4_performance",
      "severity": "HIGH",
      "rule": "AP-04 — string-concat-in-loop",
      "location": { "file": "generated_code.py", "line": 58, "col": 8 },
      "message": "String concatenation inside loop is O(n²). For n=1000 inputs, this is ~1M string copies.",
      "code_snippet": "result += chunk",
      "fix_suggestion": "Replace with: chunks = []; chunks.append(chunk); result = ''.join(chunks)",
      "docs": "https://docs.python.org/3/faq/programming.html#what-is-the-most-efficient-way-to-concatenate-strings"
    }
  ],

  "test_coverage": {
    "edge_cases_generated": 47,
    "edge_cases_passed": 45,
    "edge_cases_failed": 2,
    "failed_inputs": ["empty string ''", "NaN float"],
    "mutation_kill_rate": "78%",
    "mutation_verdict": "WARN — below 80% threshold"
  },

  "performance": {
    "memory_mb": 12.4,
    "memory_verdict": "PASS",
    "complexity_findings": [
      {
        "function": "process_records",
        "estimated": "O(n²)",
        "verdict": "WARN",
        "line": 42
      }
    ]
  },

  "human_action_required": [
    "Review HIGH finding CG-H001: mutable default argument on line 34",
    "Review HIGH finding CG-H002: O(n²) string concat on line 58",
    "Review 2 failed edge cases: empty string and NaN inputs"
  ]
}
```

---

## VERDICT DEFINITIONS

```
PASS         — All layers clean. No CRITICAL or HIGH findings.
               Code may be surfaced to human reviewer.

CONDITIONAL  — No CRITICAL findings. Has HIGH or MEDIUM findings.
               Surface to human with full findings report.
               Human must explicitly approve each HIGH finding.

FAIL         — One or more CRITICAL findings, OR parse failure,
               OR secret detected, OR CVE in critical dependency.
               Code must NOT be surfaced. Return to LLM for regeneration.
               After 3 failed regeneration attempts: escalate to human
               with full audit trail.
```

---

## PROMPT ENGINEERING RULES

When using this skill to guide an LLM's code generation, prepend the following
to every code generation prompt:

```
SYSTEM CONTEXT — CODEGUARD ACTIVE:

You are generating code that will be validated by a 4-layer static/dynamic
analysis pipeline. Write accordingly:

MANDATORY:
1. Every function MUST have type annotations (all parameters + return type)
2. Every function MUST have a docstring with: purpose, params, returns, raises
3. Use None as default for mutable parameters — never [] or {}
4. Every await call must have explicit error handling (try/except)
5. Never concatenate strings into SQL, shell commands, or HTML
6. Parameterize ALL database queries
7. Use specific exception types — never bare except:
8. Check for None/null before any attribute chain deeper than 1
9. No magic numbers — use named constants
10. Every loop variable captured by a closure must use a default arg (x=x) or factory

MUST INCLUDE IN GENERATED CODE:
- Input validation at the top of every public function
- Explicit handling for: empty input, None input, max-size input
- A comment on time complexity for any function with nested loops
- Thread-safety note on any function modifying shared state

DO NOT GENERATE:
- eval(), exec(), or __import__() with non-literal arguments
- os.system(), subprocess with shell=True
- pickle.loads() on untrusted data
- yaml.load() (use yaml.safe_load())
- MD5 or SHA1 for security purposes
- random.random() for security/tokens (use secrets module)
- f-strings building SQL queries
- Bare except: pass blocks
```

---

## LANGUAGE-SPECIFIC ADDITIONS

### Python
```
ADDITIONAL CHECKS:
- Verify all file opens use context managers (with statement)
- Verify generators are used for large dataset iteration (not list comprehension)
- Verify @dataclass fields with default mutable values use field(default_factory=list)
- Verify pathlib.Path used instead of os.path string manipulation
- Verify logging used instead of print() for non-demo code
- Verify secrets.token_hex() used for any token/ID generation
```

### Java
```
ADDITIONAL CHECKS:
- Verify Optional<T> used for nullable returns (not null)
- Verify equals() used for String comparison (not ==)
- Verify StringBuilder used for string concatenation in loops
- Verify try-with-resources for all AutoCloseable resources
- Verify Collections.unmodifiableList() for returned collections
- Verify no raw types (List instead of List<String> is a FAIL)
- Verify PreparedStatement used for all SQL (never Statement + concat)
```

### JavaScript / TypeScript
```
ADDITIONAL CHECKS:
- Verify let/const used (never var)
- Verify === used (never ==)
- Verify Promise errors are caught (.catch() or try/catch in async)
- Verify no floating Promises (must be awaited or .catch attached)
- Verify no eval() or new Function() with user input
- Verify no localStorage for sensitive data (use httpOnly cookies)
- Verify input sanitization before DOM insertion (no innerHTML with user data)
- Verify crypto.randomUUID() or crypto.getRandomValues() for IDs/tokens
```

### Kotlin
```
ADDITIONAL CHECKS:
- Verify lateinit var has isInitialized check before access
- Verify ?.let / ?: / requireNotNull() used for nullable handling
- Verify data class used for value objects (not plain class)
- Verify sealed class/interface for exhaustive when expressions
- Verify coroutineScope / supervisorScope correctly scoped
- Verify Dispatchers.IO for IO-bound coroutines (not Default)
- Verify StateFlow/SharedFlow used for shared state (not mutable var)
```

---

## CI/CD INTEGRATION

### GitHub Actions
```yaml
# .github/workflows/codeguard.yml
name: CodeGuard Validation

on: [push, pull_request]

jobs:
  codeguard:
    runs-on: ubuntu-latest
    container:
      image: codeguard:latest   # see Dockerfile below

    steps:
      - uses: actions/checkout@v4

      - name: Run CodeGuard
        run: |
          codeguard validate \
            --language auto \
            --layers all \
            --threshold CONDITIONAL \
            --output-format json \
            --report-file codeguard-report.json \
            ./src/

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: codeguard-report
          path: codeguard-report.json

      - name: Fail on CRITICAL
        run: |
          python -c "
          import json, sys
          r = json.load(open('codeguard-report.json'))
          if r['summary']['CRITICAL'] > 0:
              print('CRITICAL issues found — blocking merge')
              sys.exit(1)
          if r['verdict'] == 'FAIL':
              print('CodeGuard FAIL verdict — blocking merge')
              sys.exit(1)
          print(f'CodeGuard: {r[\"verdict\"]} — {r[\"summary\"][\"total_issues\"]} issues')
          "
```

### Jenkins Pipeline
```groovy
// Jenkinsfile
pipeline {
    agent { docker { image 'codeguard:latest' } }

    stages {
        stage('CodeGuard') {
            steps {
                sh '''
                  codeguard validate \
                    --language auto \
                    --layers all \
                    --threshold CONDITIONAL \
                    --output-format json \
                    --report-file codeguard-report.json \
                    ./src/
                '''
            }
            post {
                always {
                    archiveArtifacts 'codeguard-report.json'
                    script {
                        def report = readJSON file: 'codeguard-report.json'
                        if (report.summary.CRITICAL > 0) {
                            error("CRITICAL issues found — build blocked")
                        }
                    }
                }
            }
        }
    }
}
```

---

## DOCKER ENVIRONMENT

```dockerfile
# Dockerfile — CodeGuard validation environment
FROM python:3.12-slim AS base

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm default-jdk kotlin \
    git curl wget \
    && rm -rf /var/lib/apt/lists/*

# Python validation tools
RUN pip install --no-cache-dir \
    ruff mypy bandit semgrep \
    hypothesis mutmut \
    memory-profiler tracemalloc \
    pip-audit safety \
    radon lizard \
    detect-secrets

# JavaScript/TypeScript tools
RUN npm install -g \
    typescript eslint \
    fast-check @stryker-mutator/core \
    njsscan

# Java tools
RUN wget -q https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz \
    && tar xf spotbugs-4.8.3.tgz -C /opt/ \
    && ln -s /opt/spotbugs-4.8.3/bin/spotbugs /usr/local/bin/spotbugs

# TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

WORKDIR /workspace
COPY validate.sh /usr/local/bin/codeguard
RUN chmod +x /usr/local/bin/codeguard

ENTRYPOINT ["codeguard"]
```

---

## FILE LOCATIONS

```
project/
├── .codeguard/
│   ├── SKILL.md              ← this file
│   ├── validate.sh           ← main runner script
│   ├── config.json           ← threshold overrides per project
│   ├── rules/
│   │   ├── python.toml       ← ruff config
│   │   ├── eslint.json       ← ESLint config
│   │   ├── detekt.yml        ← Kotlin config
│   │   └── semgrep/          ← custom semgrep rules
│   └── reports/              ← generated JSON reports
└── .github/
    └── workflows/
        └── codeguard.yml     ← CI integration
```
