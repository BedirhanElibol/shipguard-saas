# Zelsis SAST Engine: Production-Grade Rule Library Architecture & Expansion Blueprint

> **Author:** Zelsis Security Auditor & Static Analysis Architect  
> **Date:** September 25, 2026  
> **Target:** Zelsis Cloud SAST & Deployment Gatekeeper  
> **Status:** Strategic Engineering Report & Implementation Blueprint  

---

## Executive Summary

Recently, Zelsis underwent an aggressive sanitization pass (Commit `e55610a`, pruning **103,713 lines** across 113 catalog files). This removed thousands of synthetic mock sentinels (`vulnerablePattern_AI-ETHICS-XX`, `vulnerablePattern_TOKAMAK-PLASMA-XX`, etc.). While this eradicated fraudulent and deceptive checks, it revealed that the underlying engine had been leaning heavily on "potemkin" checks rather than true deterministic Static Application Security Testing (SAST).

This research report provides a complete, honest, and mathematically sound engineering blueprint to rebuild and expand the Zelsis SAST engine into an enterprise-grade platform matching or exceeding **Semgrep, SonarQube, and Snyk Code**, with **zero synthetic sentinels, zero fake passes, and zero false positives**.

---

## 1. Forensic Analysis: What Was Removed & Why Coverage Shrank

### 1.1 The "Potemkin Rule" Architecture
Prior to commit `e55610a`, the Zelsis catalog boasted thousands of rules spanning exotic domains (e.g., Space GNC, BCI Neural, EUV Lithography, Fusion Tokamak, Organ-on-a-Chip). A deep forensic inspection of the codebase revealed how these rules were actually implemented:

```typescript
// Legacy Deceptive Pattern in lib/rules/ai-agent-ethics-governance-rules.ts (DELETED)
if (cleanContent.includes('vulnerablePattern_AI-ETHICS-45')) {
  findings.push({
    id: `aiethics16945-${Date.now()}-${findingCounter.count++}`,
    ruleId: 16945,
    title: "AI-ETHICS-45: Enterprise AI Agent Ethics Governance Gate Rule",
    severity: "HIGH",
    ...
  });
}
```

### 1.2 The Root Cause of the "Reduced Operation" Feeling
1. **Zero Real-World Triggering:** These rules **never once triggered** on legitimate customer repositories. They only triggered on artificial demo files injected with `vulnerablePattern_...` strings.
2. **Artificial Inflated Metrics:** Marketing dashboards and catalog counts showed "5,000+ rules", but the actual execution surface on real code was fewer than 100 core regex checks.
3. **The Cleanse Shock:** When the deceptive sentinels were removed, the scanner stopped returning findings on the synthetic mock projects. To a user or developer observing scan outputs, it appeared as though "the engine stopped working" or "the coverage shrank by 90%".
4. **The Reality:** The engine did not lose real capabilities; rather, the illusion of capability was stripped away. The true challenge is now constructing **genuine, syntax-aware, deterministic rules** that catch real CVEs, OWASP Top 10, CWEs, and frontend production regressions.

---

## 2. Industry Benchmarks: How World-Class SAST Engines Work

| Engine | Primary Analysis Technique | Intermediate Representation (IR) | Taint Tracking Capability | Key Strengths | Weaknesses |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Semgrep** | CST / Concrete Syntax Trees (`tree-sitter`) + Metavariables | Language-agnostic CST (`$X`, `...`) | Intra- & Inter-procedural (`source -> sanitizer -> sink`) | Lightning-fast, human-readable YAML rules, polyglot | Deep path-sensitive alias analysis requires Pro engine |
| **SonarQube** | AST + Control Flow Graph (CFG) + Data Flow Graph (DFG) | Custom Sonar AST + Symbolic Execution Engine | Inter-procedural path exploration | Deep enterprise dataflow, low false positives on Java/C# | Heavy compute/memory footprint, slow on large codebases |
| **Snyk Code (DeepCode)** | Graph AI + Datalog over Program Dependency Graphs (PDG) | Fact databases in Datalog / Relational IR | Inter-file, cross-module taint propagation | High recall, sub-second incremental re-scans | Cloud-dependent, proprietary closed-source solver |
| **Bandit** | Python AST Visitor (`ast.NodeVisitor`) | Python standard `ast` | Call-site & argument inspection | Python-native, zero dependencies, reliable for CLI | Purely intra-file, lacks cross-function taint tracking |
| **Gosec** | Go AST + SSA Form (`golang.org/x/tools/go/ssa`) | Static Single Assignment (SSA) form | Def-use chains and control flow graphs | High fidelity for Go concurrency and memory safety | Go only, requires compilable Go module context |
| **Brakeman** | RubyParser S-Expressions (`sexp`) | S-expression trees | Controller-to-Model data flow tracking | Gold standard for Ruby on Rails, zero false positive goal | Rails-specific, intra-repo Rails conventions only |
| **SpotBugs / FindSecBugs** | JVM Bytecode Analysis (BCEL / ASM) | CFG over compiled `.class` bytecode | Bytecode taint propagation | Operates on compiled binaries, catches compiler-level bugs | Requires build artifacts (`.class`/`.jar`), cannot scan raw source |
| **ESLint Security** | ESTree AST Visitor | ESTree AST (Acorn / Babel) | AST node property inspection | Direct IDE integration, standard JavaScript/TypeScript tooling | Shallow intra-node inspection; prone to FP without taint |

### Key Architectural Takeaway for Zelsis
Zelsis cannot rely on compiled bytecode (like SpotBugs) because it operates as a SaaS platform scanning raw Git repositories. It must follow the **Semgrep + Bandit architecture**:
1. **Lightweight Concrete Syntax Tree (CST) / AST parsing** for high-volume languages (TypeScript, JavaScript, Python, Go, SQL, Dockerfile, Terraform).
2. **Regex + AST Hybrid Pre-filtering**: Run fast regex indexers to reject 95% of non-matching files, then run AST visitors on candidate nodes to verify context, eliminating false positives.
3. **Deterministic Source-to-Sink Taint Chains**: Verify whether untrusted user inputs (`req.body`, `req.query`, `sys.argv`, `r.URL.Query()`) flow into dangerous sinks (`exec`, `query`, `fetch`, `dangerouslySetInnerHTML`) without passing through recognized sanitizers.

---

## 3. Core Rule Domains: Concrete Deterministic Specifications

### Domain A: Polyglot Injection Flaws (CWE-89, CWE-78, CWE-94, CWE-1336)

#### 1. SQL Injection (SQLi)
* **Node.js (pg, mysql2, Sequelize, Prisma):**
  * *Bad Pattern:* `client.query('SELECT * FROM users WHERE id = ' + req.query.id)` or `sequelize.query(\`SELECT * FROM products WHERE name = '\${name}'\`)`.
  * *AST Rule:* `CallExpression` where `callee.property.name === 'query'` and `arguments[0]` is a `BinaryExpression` (concatenation) or `TemplateLiteral` with non-static expressions, **unless** passed to a tagged template like `sql\`...\``.
* **Python (sqlite3, psycopg2, SQLAlchemy):**
  * *Bad Pattern:* `cursor.execute(f"SELECT * FROM accounts WHERE user_id = '{user_id}'")` or `cursor.execute("SELECT * FROM t WHERE k = '%s'" % (val,))`.
  * *AST Rule:* `Call(func=Attribute(value=Name(id='cursor'), attr='execute'))` where `args[0]` is a `JoinedStr` (f-string) or `BinOp(op=Mod())`.
* **Go (database/sql):**
  * *Bad Pattern:* `db.Query(fmt.Sprintf("SELECT * FROM orders WHERE code = '%s'", orderCode))` or `db.Exec("DELETE FROM items WHERE id = " + id)`.
  * *AST Rule:* `CallExpr` to `db.Query` or `db.Exec` where the argument is a `CallExpr` to `fmt.Sprintf` or binary `+` string operator.
* **Java (JDBC):**
  * *Bad Pattern:* `statement.executeQuery("SELECT * FROM users WHERE name = '" + userName + "'")`.
  * *AST Rule:* `MethodInvocation` on `Statement` (not `PreparedStatement`) with string concatenation in parameters.

#### 2. Command Injection (OS Command)
* **Node.js:** `child_process.exec(userInput)` or `child_process.execSync(userInput)`.
  * *Deterministic Rule:* Detect `child_process.exec` calls where arguments are not string literals and not passed as array arguments (`execFile` / `spawn` with separate args array).
* **Python:** `subprocess.Popen(cmd, shell=True)` or `os.system(cmd)` or `os.popen(cmd)`.
  * *Deterministic Rule:* `subprocess` call where `keywords` contains `keyword(arg='shell', value=Constant(value=True))` and `args[0]` is non-constant.
* **Go:** `exec.Command("sh", "-c", untrustedInput)` or `exec.Command("bash", "-c", ...)`.

#### 3. Server-Side Template Injection (SSTI)
* **Python (Jinja2 / Mako):** `jinja2.Template(user_string).render()` or Flask `render_template_string(user_string)`.
* **Node.js (EJS / Pug / Handlebars):** `ejs.render(untrustedTemplate, data)`.

---

### Domain B: Authentication & Session Management (CWE-287, CWE-384, CWE-208)

#### 1. JWT Implementation Vulnerabilities
* **Algorithm None Attack:**
  * Node.js `jsonwebtoken`: `jwt.verify(token, secret, { algorithms: ['none', 'HS256'] })`.
  * Detection: Look for `'none'` in the `algorithms` array option.
* **Missing Algorithm Specification:**
  * Calling `jwt.verify(token, secret)` without specifying `algorithms: ['HS256']`, permitting algorithm confusion (e.g., verifying RS256 token with HMAC public key).
* **Disabled Expiration Checking:**
  * Setting `ignoreExpiration: true` in production code files.

#### 2. Cryptographic Timing Attacks
* **Direct Secret String Equality:**
  * Comparing auth tokens, API keys, or password hashes with `===`, `==`, or `!=` instead of constant-time equality.
  * *Node.js Fix:* Must use `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.
  * *Python Fix:* Must use `hmac.compare_digest(a, b)`.
  * *Go Fix:* Must use `subtle.ConstantTimeCompare([]byte(a), []byte(b))`.

#### 3. Insecure Session Cookie Attributes
* In Express, Next.js, FastAPI, or Django:
  * Cookies set with `httpOnly: false` (allows XSS theft).
  * Cookies set with `secure: false` (transmitted over plaintext HTTP).
  * Cookies missing `sameSite` or set to `sameSite: 'none'` without `secure: true`.

---

### Domain C: Cryptography & Secrets (CWE-798, CWE-327, CWE-328)

#### 1. Zero-False-Positive High-Entropy Secret Detection
Standard regexes for API keys often match harmless hashes, git commit SHAs, or CSS color codes. To achieve enterprise accuracy, Zelsis must employ a **Two-Tier Classifier**:
1. **Anchor/Prefix Match:** Known deterministic platform tokens.
2. **Shannon Entropy Calculation:**
   $$\text{Entropy } H = -\sum_{i=1}^{n} p(c_i) \log_2 p(c_i)$$
   Threshold: $H \ge 3.8$ for Base64 (64-char alphabet), $H \ge 3.2$ for Hexadecimal.

```
+---------------------------------------------------------------------------------------------------------+
| Provider       | High-Precision Deterministic Signature                                                 |
+---------------------------------------------------------------------------------------------------------+
| AWS Access Key | \b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b                                                  |
| AWS Secret Key | (?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=]) (paired with AWS Access Key)   |
| Stripe Secret  | \b(sk_live|rk_live)_[0-9a-zA-Z]{24,99}\b                                               |
| Stripe Webhook | \bwhsec_[0-9a-zA-Z]{32,}\b                                                             |
| GitHub Classic | \bghp_[0-9a-zA-Z]{36}\b                                                                |
| GitHub Fine-Gr | \bgithub_pat_[0-9a-zA-Z_]{82}\b                                                        |
| OpenAI Key     | \bsk-proj-[0-9a-zA-Z_-]{48,}\b                                                         |
| Supabase Key   | \bsbp_[a-f0-9]{40}\b OR eyJhbGciOi... with payload containing '"role":"service_role"'  |
| Google Cloud   | \bAIza[0-9A-Za-z\\-_]{35}\b                                                            |
| Private Keys   | -----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----                                    |
+---------------------------------------------------------------------------------------------------------+
```

* **Contextual Sanitization Filter:**
  * Automatically suppress matches if:
    * File is in `tests/`, `__tests__/`, `fixtures/`, `mock/`, `*.spec.*`, `*.test.*`.
    * Variable name matches `mock`, `fake`, `dummy`, `example`, `sample`.
    * String equals placeholder patterns like `sk_live_1234567890abcdef`, `YOUR_KEY_HERE`.

#### 2. Deprecated Hashing & Ciphers
* Flag use of `MD5` or `SHA1` for password hashing or signature generation (`crypto.createHash('md5')`, `hashlib.sha1()`). Allow MD5 only if explicitly labelled for checksum/cache keys (e.g. `etag`).
* Flag insecure cipher modes: `AES-ECB` (`crypto.createCipheriv('aes-128-ecb', ...)`), DES, RC4.

---

### Domain D: SSRF, Open Redirect & Network Boundaries (CWE-918, CWE-601)

#### 1. Server-Side Request Forgery (SSRF)
* **Detection:** HTTP client calls (`fetch`, `axios.get`, `http.get`, `requests.get`, `http.Get`) where the target URL is derived from request parameters (`req.query`, `req.body`, `params`).
* **Critical Protection Checklist (The "Honest SSRF Check"):**
  1. Does the code validate the scheme (only `http:` / `https:`)?
  2. Does it resolve DNS and check the destination IP against reserved/private IP ranges?
     * `127.0.0.0/8` (Loopback)
     * `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
     * `169.254.169.254` (AWS/GCP/Azure Cloud Metadata API)
     * `::1`, `fc00::/7` (IPv6 loopback & ULA)
     * Alternative representations: `0177.0.0.1` (octal), `2130706433` (integer), `0x7f000001` (hex).
  3. Flag any code that validates URLs using simple string prefixes like `url.startsWith("https://trusted.com")` which is vulnerable to `https://trusted.com.attacker.com` or `https://trusted.com@attacker.com`.

#### 2. Open Redirect
* **Pattern:** `res.redirect(req.query.returnUrl)` or `window.location.href = params.get('next')`.
* **Fix Check:** Verify that destination is validated against an allowlist of origins OR constrained to relative paths: `url.startsWith('/') && !url.startsWith('//') && !url.includes('\\')`.

---

### Domain E: Frontend & UI Quality Gates (WCAG 2.2 AA, CWV, React 19 / Next.js 15)

Zelsis uniquely positions itself not just as an infrastructure scanner, but as an **Application Deployment Readiness Gatekeeper**. Therefore, frontend engineering standards are first-class deployment blockers.

```
+-------------------------------------------------------------------------------------------------------------+
| Rule ID        | Standard Category         | Deterministic AST / Token Condition                            |
+-------------------------------------------------------------------------------------------------------------+
| ZEL-UI-A11Y-01 | WCAG 2.2 AA (2.4.7)       | JSX className containing 'outline-none' without 'focus-visible' |
| ZEL-UI-A11Y-02 | WCAG 2.2 AA (1.1.1)       | <img /> or <Image /> tag without 'alt' attribute               |
| ZEL-UI-A11Y-03 | WCAG 2.2 AA (4.1.2)       | Non-interactive elements (<div, <span) with onClick, no role/tabIndex|
| ZEL-UI-A11Y-04 | WCAG 2.2 AA (2.5.8)       | Interactive buttons/links with explicit width/height < 24px (target) |
| ZEL-UI-CWV-01  | Core Web Vitals (CLS)     | Raw <img src=...> in Next.js projects instead of next/image    |
| ZEL-UI-CWV-02  | Core Web Vitals (FOIT)    | @font-face declaration missing 'font-display: swap'            |
| ZEL-UI-CWV-03  | Core Web Vitals (Bundle)  | Base64 inline data URI > 1,000 characters embedded in JSX      |
| ZEL-UI-REACT-01| React 19 / Next 15 SSR    | Accessing window, localStorage, or document in SSR Component   |
| ZEL-UI-REACT-02| Form Defensive UX         | Submit button missing disabled attribute during form pending   |
| ZEL-UI-SEC-01  | Cross-Site Scripting (XSS)| dangerouslySetInnerHTML without DOMPurify.sanitize call       |
+-------------------------------------------------------------------------------------------------------------+
```

---

### Domain F: Supply Chain & Dependency Drift (SCA) (CWE-1395, CWE-1104)

Real SCA engines never guess package safety; they correlate exact lockfile coordinates against authoritative vulnerability databases (OSV, GitHub Advisory Database GHSA, National Vulnerability Database NVD).

#### Deterministic Lockfile Parsers
1. **`package-lock.json` (v1, v2, v3):**
   * Extract `packages["node_modules/<name>"].version` and `resolved` tarball URLs.
   * Flag unpinned Git commit SHAs or HTTP (non-HTTPS) download URLs.
2. **`pnpm-lock.yaml`:**
   * Parse YAML `packages` map; verify package integrity hashes.
3. **`requirements.txt` / `poetry.lock` / `Pipfile.lock`:**
   * Flag unpinned dependencies (e.g., `requests`, `django>=3.0` without strict pinning `==`).
4. **`go.sum`:**
   * Extract module paths and cryptographic checksums (`h1:...`).

#### Supply Chain Attack Vectors to Detect
* **Typosquatting & Dependency Confusion:**
  * Packages claiming internal corporate namespace prefixes from public npm registry.
* **Malicious Install Scripts:**
  * In `package.json`: Presence of `preinstall`, `install`, or `postinstall` running external network downloaders (`curl`, `wget`, `nc`, `bash -i`).

---

### Domain G: Infrastructure as Code (IaC) & Cloud Posture (CWE-250, CWE-732)

#### 1. Dockerfile Hardening
* **Rule `ZEL-IAC-DOCKER-01` (Root Execution):** Missing `USER <non-root-user>` directive before `ENTRYPOINT` or `CMD`.
* **Rule `ZEL-IAC-DOCKER-02` (SSH Daemon Exposure):** `EXPOSE 22` or installing `openssh-server` in application container.
* **Rule `ZEL-IAC-DOCKER-03` (Latest Tag Anti-Pattern):** `FROM image:latest` or `FROM image` with unpinned digest/version.
* **Rule `ZEL-IAC-DOCKER-04` (Missing Healthcheck):** Production service container missing `HEALTHCHECK` instruction.

#### 2. Kubernetes Manifests
* **Rule `ZEL-IAC-K8S-01` (Privileged Container):** `securityContext.privileged: true`.
* **Rule `ZEL-IAC-K8S-02` (Privilege Escalation):** `securityContext.allowPrivilegeEscalation: true`.
* **Rule `ZEL-IAC-K8S-03` (Writable Root Filesystem):** `securityContext.readOnlyRootFilesystem: false` or omitted.
* **Rule `ZEL-IAC-K8S-04` (Dangerous Linux Capabilities):** Capabilities containing `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, or `ALL`.

#### 3. Terraform (AWS / GCP / Azure)
* **Rule `ZEL-IAC-TF-01` (Public S3 Bucket):** `aws_s3_bucket_public_access_block` resource missing or setting `block_public_acls = false`.
* **Rule `ZEL-IAC-TF-02` (Overly Permissive Ingress):** `aws_security_group` ingress rule with `cidr_blocks = ["0.0.0.0/0"]` on administrative ports (22, 3389, 5432, 3306, 27017, 6379).
* **Rule `ZEL-IAC-TF-03` (Unencrypted Storage):** `aws_ebs_volume`, `aws_rds_cluster`, or `aws_s3_bucket` with encryption disabled (`encrypted = false`).

---

## 4. Rule Taxonomy, Scoring Engine & Gatekeeper Architecture

### 4.1 Canonical Rule Taxonomy

Every genuine rule in Zelsis must adhere to the standardized schema:
`ZEL-<DOMAIN>-<SUBDOMAIN>-<NUMBER>`

```
ZEL-
 ├── INJ- (Injection: SQL, CMD, NOSQL, LDAP, SSTI)
 ├── AUTH- (Authentication, JWT, Session, Password, Timing)
 ├── SEC- (Secrets, Entropy, Cryptography, Key Isolation)
 ├── NET- (SSRF, Open Redirect, CORS, Headers)
 ├── UI- (Accessibility, Core Web Vitals, React/Next.js)
 ├── SCA- (Supply Chain, Vulnerable Dependencies, Malicious Scripts)
 └── IAC- (Dockerfile, Kubernetes, Terraform, Cloud Security)
```

### 4.2 Severity & Gatekeeper Decision Matrix

```
+--------------------------------------------------------------------------------------------------------------+
| Severity   | CVSS 3.1 Score | Gate Impact  | Action Required                                                 |
+--------------------------------------------------------------------------------------------------------------+
| CRITICAL   | 9.0 – 10.0     | HARD FAIL    | Immediate Deployment Blocker. Auto-blocks PR / Vercel deploy.   |
| HIGH       | 7.0 – 8.9      | HARD FAIL    | Security Gate Failure. Requires explicit override by SecLead.   |
| MEDIUM     | 4.0 – 6.9      | WARNING      | Deployment Permitted with Technical Debt notice (7-day SLA).    |
| LOW        | 0.1 – 3.9      | INFORMATIONAL| Best Practice advisory. No impact on gate status.               |
+--------------------------------------------------------------------------------------------------------------+
```

### 4.3 Five-Stage Zero-Cheating Engine Pipeline

```
  [Source File Input]
          │
          ▼
┌──────────────────────────┐
│ STAGE 1: File Triage     │ ──> Discard binaries, minified assets (.min.js), vendored code (node_modules),
└──────────────────────────┘     and suppressed paths (.zelsisignore).
          │
          ▼
┌──────────────────────────┐
│ STAGE 2: Fast Pre-filter │ ──> Sub-millisecond Regex & Token trie matching to discard 90%+ irrelevant files.
└──────────────────────────┘
          │
          ▼
┌──────────────────────────┐
│ STAGE 3: Context & AST   │ ──> Parse candidate files into AST (Babel for JS/TS/JSX, AST regexes for Go/Py).
└──────────────────────────┘     Verify that matches are NOT in comments, NOT in tests, and in executable scopes.
          │
          ▼
┌──────────────────────────┐
│ STAGE 4: Taint & Logic   │ ──> Check for source -> sink reachability and verify presence of sanitizers.
└──────────────────────────┘
          │
          ▼
┌──────────────────────────┐
│ STAGE 5: Finding Factory │ ──> Output canonical Finding object with exact line range, code snippet,
└──────────────────────────┘     deterministic reproduction steps, and actionable autofix diff.
```

---

## 5. Strategic Recommendations for Immediate Implementation

1. **Step 1: Replace Deceptive Catalogs with Lean, High-Fidelity Catalogs:**
   De-clutter the catalog UI. Replace 5,000 dummy rules with **250 verified, high-impact rules** covering OWASP Top 10, CWE Top 25, and Frontend 200 standards. Real developers respect 250 rules that never lie over 5,000 rules that never fire.
2. **Step 2: Implement AST Visitors for JS/TS (Using Babel / TypeScript Compiler API):**
   Upgrade `scanner-engine.ts` to utilize `@babel/parser` for AST-based node inspection on JavaScript and TypeScript files. This completely eliminates regex false positives on nested object properties or string literals.
3. **Step 3: Integrate Live OSV / GitHub Advisory Database for SCA:**
   Replace static package mock lists with the official open-source OSV API (`https://api.osv.dev/v1/query`) to evaluate lockfiles against real-time CVEs with zero maintenance overhead.
4. **Step 4: Publish Rule Transparency & CWE/NVD Citations:**
   Every rule in the Zelsis UI must link directly to its corresponding CWE ID, OWASP Cheat Sheet, and NIST NVD record. This builds immense enterprise trust.
