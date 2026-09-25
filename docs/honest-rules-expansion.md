# Zelsis Honest SAST Rule Expansion Architecture & Taxonomy
**Document Version:** 1.0.0  
**Classification:** Engineering Specification  
**Status:** Approved Architecture Blueprint  

---

## 1. Executive Directive & The Zero-Sentinel Standard

### 1.1 The Problem with Legacy & Synthetic SAST
Historically, security scanners frequently rely on artificial string triggers (e.g. `cleanContent.includes("vulnerableSentinelToken")` or hardcoded variable names) to simulate test passage. This practice produces catastrophic blind spots in production:
1. **Blind False Negatives:** Real-world production code rarely uses toy variable names like `unvalidatedUrl` or `evalPayload`. Real attacks exploit natural variable names (`req.body.id`, `params.callback`).
2. **Artificial Pass/Fail:** Scanners pass artificial benchmarks while completely failing on production codebases.
3. **Developer Mistrust:** Developers lose confidence when a tool reports either zero real issues or dozens of false flags.

### 1.2 Zelsis Zero-Sentinel Guarantee
In Zelsis, every rule is required to operate on **deterministic Abstract Syntax Tree (AST) patterns**, **regular expressions with lexical boundaries**, and **context-aware semantic analysis**.
- **No Synthetic Sentinels:** No rule may test for artificial marker strings.
- **Zero-Tolerance for False Negatives:** AST parsers analyze expression call sites, callee identifiers, argument types, and control flow paths.
- **Explainable Remediation:** Every finding must provide an exact file, line number, code snippet, OWASP/CWE category, and an actionable patch.

---

## 2. Multi-Framework Deterministic Rule Catalog

The following rules form the core expansion blueprint across modern enterprise frameworks: Next.js 15, Python (FastAPI/Django), Go (Golang), and Node.js.

### 2.1 Next.js 15 & React Server Components (RSC)

#### Rule: `NEXT15-ACT-01` — Missing Server Action Authentication & Session Verification
- **Rule ID:** `15001`
- **Severity:** `CRITICAL`
- **CWE / OWASP:** CWE-306 (Missing Authentication for Critical Function) / OWASP A01:2021-Broken Access Control
- **Detection Algorithm:**
  1. Inspect TypeScript/JavaScript files containing `'use server'` directive (at file level or function block).
  2. Parse exported async functions (Server Actions).
  3. Analyze AST body for session resolution calls (e.g., `auth()`, `getServerSession()`, `supabase.auth.getUser()`, `cookies().get('session')`).
  4. Flag exported server actions performing database mutations (`prisma.*.create`, `db.query`, `supabase.from().insert()`) that lack session verification prior to execution.
- **Code Pattern:**
  ```typescript
  // VULNERABLE:
  'use server';
  export async function deleteProject(id: string) {
    await db.project.delete({ where: { id } }); // Missing auth check!
  }

  // SECURE REMEDIATION:
  'use server';
  export async function deleteProject(id: string) {
    const session = await auth();
    if (!session?.user) throw new Error('Unauthorized');
    await db.project.delete({ where: { id, userId: session.user.id } });
  }
  ```

#### Rule: `NEXT15-ENV-01` — Server-Side Secret Exposed in `NEXT_PUBLIC_` Scope
- **Rule ID:** `15002`
- **Severity:** `CRITICAL`
- **CWE / OWASP:** CWE-200 (Exposure of Sensitive Information) / OWASP A05:2021-Security Misconfiguration
- **Detection Algorithm:**
  1. Scan `.env*`, `next.config.js/ts`, and client `.tsx` files.
  2. Regex match identifiers: `NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|DATABASE_URL|MASTER_KEY)`.
  3. Validate variable assignment value against high-entropy secrets or private service patterns.
- **Remediation:** Remove `NEXT_PUBLIC_` prefix; move the secret access exclusively to Server Components or Route Handlers (`process.env.SUPABASE_SERVICE_ROLE_KEY`).

---

### 2.2 Python (FastAPI & SQLAlchemy 2.0)

#### Rule: `PY-FASTAPI-01` — Raw SQL Interpolation in Async SQLAlchemy Sessions
- **Rule ID:** `15101`
- **Severity:** `CRITICAL`
- **CWE / OWASP:** CWE-89 (SQL Injection) / OWASP A03:2021-Injection
- **Detection Algorithm:**
  1. Scan Python files (`.py`) importing `sqlalchemy` or `databases`.
  2. Match AST call sites: `session.execute(text(...))` or `db.execute(...)`.
  3. Flag occurrences where `text(...)` contains Python f-strings (`text(f"SELECT ... {var}")`) or `%` string formatting (`text("... %s" % var)`).
- **Code Pattern:**
  ```python
  # VULNERABLE:
  await session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))

  # SECURE REMEDIATION:
  await session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
  ```

#### Rule: `PY-DESER-01` — Insecure Object Deserialization via `pickle` or `yaml.load`
- **Rule ID:** `15102`
- **Severity:** `CRITICAL`
- **CWE / OWASP:** CWE-502 (Deserialization of Untrusted Data) / OWASP A08:2021-Software and Data Integrity
- **Detection Algorithm:**
  1. Match call expressions: `pickle.loads(...)`, `_pickle.loads(...)`, `dill.loads(...)`.
  2. Match `yaml.load(...)` calls lacking `Loader=yaml.SafeLoader` or `Loader=yaml.CSafeLoader`.
- **Remediation:** Enforce `yaml.safe_load(data)` or replace `pickle` with validated JSON/Pydantic schemas.

---

### 2.3 Go (Golang 1.22+)

#### Rule: `GO-RACE-01` — Goroutine Closure Variable Capture Race Condition
- **Rule ID:** `15201`
- **Severity:** `HIGH`
- **CWE / OWASP:** CWE-362 (Race Condition) / OWASP A04:2021-Insecure Design
- **Detection Algorithm:**
  1. Parse Go AST for `for` / `range` loop blocks containing `go func() { ... }()` invocations.
  2. Detect loop iteration variables referenced inside the anonymous goroutine closure without being passed as explicit arguments.
- **Code Pattern:**
  ```go
  // VULNERABLE:
  for _, item := range items {
      go func() {
          process(item) // Race condition in Go < 1.22!
      }()
  }

  // SECURE REMEDIATION:
  for _, item := range items {
      go func(it Item) {
          process(it)
      }(item)
  }
  ```

#### Rule: `GO-TMPL-01` — Unescaped HTML Injection via `template.HTML` Type Cast
- **Rule ID:** `15202`
- **Severity:** `HIGH`
- **CWE / OWASP:** CWE-79 (Cross-Site Scripting) / OWASP A03:2021-XSS
- **Detection Algorithm:**
  1. Parse Go call sites using `html/template`.
  2. Flag raw type conversion `template.HTML(untrustedVar)` where `untrustedVar` originates from HTTP request bodies, URL query parameters, or database results.
- **Remediation:** Use standard Go contextual auto-escaping in templates or pass through `bluemonday` sanitizer before type conversion.

---

### 2.4 Universal Database Gate (PostgreSQL, MySQL, MongoDB, Redis)

#### Rule: `DB-INJ-01` — Unparameterized Dynamic Query Concatenation (Multi-Engine)
- **Rule ID:** `15301`
- **Severity:** `CRITICAL`
- **CWE / OWASP:** CWE-89 (SQL Injection) / OWASP A03:2021-Injection
- **Engines Audited:** PostgreSQL (`pg`, `postgres.js`), MySQL (`mysql2`), SQLite (`better-sqlite3`).
- **Detection Algorithm:**
  1. Detect driver query execution call sites: `pool.query(...)`, `client.query(...)`, `db.query(...)`.
  2. Analyze first parameter: Flag binary expression `+` concatenations, template literals with variable interpolation (`${var}`), or unescaped string joins.

#### Rule: `NOSQL-INJ-01` — MongoDB Dynamic `$where` or Unvalidated Object Filter Injection
- **Rule ID:** `15302`
- **Severity:** `CRITICAL`
- **CWE / OWASP:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **Detection Algorithm:**
  1. Scan Mongoose/MongoDB collections: `find(...)`, `findOne(...)`, `updateOne(...)`.
  2. Flag query objects containing `$where` properties accepting string concatenations or raw client-provided parameter objects without type assertions.
- **Remediation:** Disable `$where` clauses and validate request bodies using strict Zod or Joi schemas with `{ sanitizeFilter: true }`.

#### Rule: `REDIS-AUTH-01` — Unauthenticated Redis Client Connection or Exposed `FLUSHALL`
- **Rule ID:** `15303`
- **Severity:** `HIGH`
- **CWE / OWASP:** CWE-306 (Missing Authentication) / OWASP A05:2021-Security Misconfiguration
- **Detection Algorithm:**
  1. Match `createClient(...)` or `new Redis(...)` configurations.
  2. Flag missing `password` / `tls` properties or URLs lacking credentials when pointing to non-localhost environments (`redis://example.com:6379`).
- **Remediation:** Enforce TLS encryption (`rediss://`) and require `REDIS_PASSWORD` in connection configurations.

---

## 3. Shannon Entropy & Format-Aware Secret Detection

### 3.1 Mathematical Principle
Shannon entropy measures the uncertainty or information density in a sequence of characters:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

High entropy ($H > 4.2$) strongly correlates with cryptographic keys, base64 strings, and API secrets, distinguishing them from human language ($H \approx 2.5 - 3.2$).

### 3.2 Format-Aware Pattern Matrix
Zelsis combines high-entropy calculation with prefix/format validation to eliminate false positives on random English words:

| Provider | Format Regex | Entropy Threshold | Severity |
|---|---|---|---|
| **Stripe Live Secret** | `\brk_live_[0-9a-zA-Z]{24,34}\b` | $H \ge 3.8$ | `CRITICAL` |
| **OpenAI Secret Key** | `\bsk-(?:proj-)?[a-zA-Z0-9_-]{48,}\b` | $H \ge 4.2$ | `CRITICAL` |
| **AWS Access Key ID** | `\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b` | Deterministic Format | `CRITICAL` |
| **AWS Secret Access Key** | `\b[A-Za-z0-9/+=]{40}\b` (with contextual var) | $H \ge 4.5$ | `CRITICAL` |
| **GitHub Personal Token** | `\bgh[pousr]_[A-Za-z0-9_]{36,255}\b` | Deterministic Format | `CRITICAL` |
| **Supabase Service Role** | `\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b` | JWT Signature Check | `CRITICAL` |
| **SSH Private Key** | `-----BEGIN (?:RSA\|EC\|OPENSSH\|DSA) PRIVATE KEY-----` | Literal Marker | `CRITICAL` |

---

## 4. Scan Execution & Performance Guardrails

1. **Worker Threading / Micro-Batches:** File scanning is batched across chunks to prevent blocking event loops.
2. **Path Pruning:** Directories such as `.git`, `node_modules`, `dist`, `.next`, `venv`, and `vendor` are skipped unconditionally before reading disk buffers.
3. **Execution Cap:** AST evaluation across an entire enterprise repository (500+ files) must complete in under **15 seconds**.
4. **SARIF v2.1.0 Export:** All findings automatically generate compliant OASIS SARIF output for GitHub Code Scanning and CI/CD gates.
