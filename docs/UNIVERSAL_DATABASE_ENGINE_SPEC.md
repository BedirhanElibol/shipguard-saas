# Zelsis SaaS — Universal Database-Agnostic Engine & Security/Readiness Gate Specification

> **Document Version:** 2.0.0  
> **Role:** Lead Database Architect, Zelsis SaaS  
> **Status:** APPROVED & ARCHITECTED  
> **Scope:** Multi-Database Audit Engine, AST Rules Taxonomy, Storage Decoupling, and Polyglot Product Positioning  

---

## Executive Summary

Zelsis is not a Supabase-specific tool. While Zelsis's **Internal Platform** utilizes Supabase / PostgreSQL for its high-performance analytics, multi-tenant row-level security (RLS), and async job queue, the **Zelsis Audit & Readiness Engine** is 100% database-agnostic, polyglot, and universally applicable.

Customers connect any application codebase—regardless of whether they run MySQL, MongoDB, Redis, SQLite, MSSQL, Oracle, DynamoDB, Elasticsearch, or Pinecone. The Zelsis Engine parses ASTs, detects drivers/ORMs, identifies vulnerability vectors, audits migration safety, and enforces strict production deployment readiness gates across 20+ storage engines.

```
+---------------------------------------------------------------------------------------------------+
|                                      ZELSIS SAAS ARCHITECTURE                                     |
+---------------------------------------------------------------------------------------------------+
|  [Zelsis SaaS Platform Internal Storage]                     [Customer Target Repositories]       |
|  - PostgreSQL + Supabase                                    - Polyglot Tech Stacks               |
|  - Auth, Profiles, Billing (Stripe)                          - Any Database Engine                 |
|  - Scan Jobs Queue (pg_cron/triggers)                        - Any ORM or Native Driver           |
|  - Immutable Finding History & Audit Ledger                  - Multi-Cloud / Bare Metal / Local   |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
                   +---------------------------------------------------------------+
                   |          UNIVERSAL DATABASE-AGNOSTIC SCANNER ENGINE           |
                   |  (Parser -> AST Traversal -> Semantic Analysis -> Gate Status)|
                   +---------------------------------------------------------------+
                     /             |               |              |             \
            +------------+  +-------------+  +-----------+  +------------+  +------------+
            | Relational |  |    NoSQL    |  | In-Memory |  |   Search   |  |   Vector   |
            | MySQL/PG/  |  | Mongo/Dynamo|  | Redis/    |  | Elastic/   |  | Pinecone/  |
            | MSSQL/SQLit|  | Firestore   |  | Memcached |  | Meili/Neo4j|  | Qdrant/Weav|
            +------------+  +-------------+  +-----------+  +------------+  +------------+
```

---

## 1. Architectural Boundary Distinction

To eliminate confusion between the host platform and audited workloads, Zelsis maintains a strict architectural partition:

### 1.1 Zelsis Internal SaaS Platform Database
- **Role:** The control plane and storage layer for Zelsis SaaS operations.
- **Technology:** Managed PostgreSQL with Supabase extensions (`uuid-ossp`, `pgcrypto`).
- **Data Domains:**
  - `profiles`: User credentials, organization affiliations, role-based access control (RBAC), subscription tiers.
  - `subscriptions`: Stripe billing status, quota tracking, seat licenses.
  - `projects`: Target repository URLs, VCS tokens, webhook secrets, custom gate thresholds.
  - `scans` & `scan_jobs`: Asynchronous scan runner queues, worker orchestration, telemetry logs.
  - `findings`: Canonical findings table with CVSS scores, remediation diffs, false-positive states.
  - `audit_logs`: SOC2 / ISO 27001 tamper-evident operational logs.
- **Isolation Guarantee:** Multi-tenant Row-Level Security (RLS) ensures tenant data never leaks across workspace boundaries.

### 1.2 User Target Projects (Audited Workloads)
- **Role:** Customer applications, microservices, mobile apps, and infrastructure-as-code submitted for deployment evaluation.
- **Technology Agnostic:** Zero requirements on the user's infrastructure.
- **Scanning Mode:** Static Code Analysis (SAST), Abstract Syntax Tree (AST) inspection, schema migration validation, configuration auditing, and container/infrastructure parsing.
- **Supported Environments:** Serverless (AWS Lambda, Vercel, Cloudflare Workers), Kubernetes, Docker Compose, Monorepos, Distributed Microservices, Mobile Apps (React Native, Flutter, Swift, Kotlin), Embedded systems.

---

## 2. Universal Database Support Matrix

The Zelsis engine supports 5 primary database paradigms spanning over 20 storage technologies:

| Paradigm | Engines Supported | Typical Drivers / ORMs Scanned | Critical Vulnerability & Readiness Vectors |
| :--- | :--- | :--- | :--- |
| **Relational (SQL)** | PostgreSQL, MySQL, MariaDB, SQLite, Microsoft SQL Server (MSSQL), Oracle DB | Prisma, Drizzle, TypeORM, SQLAlchemy, GORM, Hibernate, Entity Framework, Sequelize, Knex, PDO, psycopg2, mysql2 | SQL Injection, unparameterized strings, connection pool exhaustion in serverless, missing indexes on FKs, destructive migrations (`DROP COLUMN`), lock contention. |
| **NoSQL / Document** | MongoDB, AWS DynamoDB, CouchDB, Google Cloud Firestore / Firebase Realtime DB | Mongoose, Motor, Spring Data MongoDB, AWS SDK (v2/v3 DynamoDB DocumentClient), Boto3, PynamoDB, Google Cloud SDK | NoSQL Injection (`$where`, `$gt`, `$ne`, unescaped regex), BSON prototype pollution, unindexed queries triggering collection scans, permissive Firestore security rules, client-side write access. |
| **In-Memory & Cache** | Redis, Dragonfly, Memcached, KeyDB | ioredis, node-redis, redis-py, go-redis, Jedis, StackExchange.Redis | Unauthenticated instances (`redis.conf` bind `0.0.0.0`), Lua script injection via `EVAL`, blocking commands in production (`KEYS *`, `FLUSHALL`), connection leaks per request in serverless. |
| **Graph & Search** | Neo4j, Elasticsearch, OpenSearch, Meilisearch | neo4j-driver, py2neo, @elastic/elasticsearch, opensearch-py, meilisearch-js | Cypher injection in Neo4j string queries, Elasticsearch unauthenticated REST endpoints (port 9200), expensive wildcard queries (`*query*`) triggering cluster CPU spikes, index mapping explosion. |
| **Vector & AI Stores** | pgvector, Pinecone, Qdrant, Weaviate, Milvus, ChromaDB, FAISS | LangChain, LlamaIndex, @pinecone-database/pinecone, qdrant-client, pymilvus | Embedding dimensionality mismatches, unindexed vector collections (brute-force KNN latency), missing tenant namespace isolation in vector indexes, unauthenticated vector API endpoints. |

---

## 3. Multi-Database AST Rules & Audit Taxonomy

Zelsis evaluates database interactions through specialized semantic AST and regex parsers. The taxonomy below outlines the core rules enforced for each database engine and ORM:

### 3.1 MySQL & MariaDB
- **`MYSQL-SEC-01: Direct SQL String Interpolation` (Critical / OWASP A03)**
  - *Pattern:* Variable concatenation or template literals passed to `db.query()`, `mysql2.execute()`, or PHP `mysqli_query()`.
  - *AST Rule:* CallExpression where `callee.property.name === 'query'` and `arguments[0]` is a BinaryExpression (`+`) or TemplateLiteral without parameter array binding.
  - *Remediation:* Enforce parameterized query: `db.query('SELECT * FROM users WHERE id = ?', [userId])`.
- **`MYSQL-SEC-02: Legacy Unbuffered / Unparameterized Driver Usage` (High)**
  - *Pattern:* Detection of deprecated `mysql` (v1) NPM package or PHP `mysql_*` functions without prepared statement support.
  - *Remediation:* Migrate to `mysql2/promise` with prepared statements or PDO with `PDO::ATTR_EMULATE_PREPARES => false`.
- **`MYSQL-CONF-03: Hardcoded Root or Default Credentials` (Critical)**
  - *Pattern:* Connection URLs or config maps containing `user: "root"`, `password: ""`, or connection string `mysql://root:...@localhost`.
  - *Remediation:* Extract credentials to environment variables and enforce non-root database users with principle of least privilege.
- **`MYSQL-PERF-04: Serverless Connection Pool Starvation` (High)**
  - *Pattern:* Creating `mysql.createPool()` or `mysql.createConnection()` inside Next.js/AWS Lambda request handler bodies without connection pooling proxy (PlanetScale, AWS RDS Proxy).
  - *Remediation:* Lift pool instantiation to module scope or integrate connection pooler.

### 3.2 MongoDB & Document Databases
- **`MONGO-SEC-01: NoSQL Injection via Tainted Query Operators` (Critical)**
  - *Pattern:* Passing raw HTTP input (`req.body`, `req.query`) directly into Mongoose `find({ username: req.body.username })` without sanitization. An attacker supplying `{"username": {"$ne": null}}` bypasses authentication.
  - *AST Rule:* ObjectExpression in query argument containing variable identifier derived from request object without sanitization (`mongo-sanitize` or Zod string schema).
  - *Remediation:* Sanitize inputs with `mongo-sanitize` or validate strictly as `z.string()`.
- **`MONGO-SEC-02: Arbitrary JavaScript Execution via $where / mapReduce` (Critical)**
  - *Pattern:* Usage of `$where: "this.name == '" + input + "'"` allowing Remote Code Execution (RCE) on the MongoDB server.
  - *Remediation:* Ban `$where` with string interpolation; replace with native MongoDB aggregation pipeline operators (`$expr`, `$eq`).
- **`MONGO-PERF-03: Unindexed Queries & Collection Scans (COLLSCAN)` (High)**
  - *Pattern:* Queries on fields missing from Mongoose schema index definitions (`index: true` or `schema.index({ field: 1 })`).
  - *Remediation:* Add compound or single-field indexes; prevent in-memory sorting over 32MB limit.

### 3.3 Redis & In-Memory Stores
- **`REDIS-SEC-01: Unauthenticated Instance & Binding to 0.0.0.0` (Critical)**
  - *Pattern:* `redis.conf` with `protected-mode no` or `bind 0.0.0.0` without `requirepass`; client connections without `password` or TLS (`rediss://`).
  - *Remediation:* Enforce TLS (`rediss://`), strong authentication, and restrict binding to `127.0.0.1` or private VPC subnet.
- **`REDIS-SEC-02: Lua Script Injection in EVAL / EVALSHA` (Critical)**
  - *Pattern:* `redis.eval("return redis.call('get', '" + userKey + "')")` interpolating dynamic inputs instead of passing them via `ARGV[1]`.
  - *Remediation:* Use parameterized Lua arguments: `redis.eval(script, 1, key, userVal)`.
- **`REDIS-PERF-03: Blocking Commands in Event Loop (KEYS *, FLUSHALL)` (High)**
  - *Pattern:* Calling `redis.keys('*')` or `FLUSHALL` in API handlers, freezing Redis single-threaded event loop.
  - *Remediation:* Replace `KEYS` with non-blocking cursor iteration `SCAN`, `HSCAN`, or `SSCAN`.
- **`REDIS-RESIL-04: Client Instance Leaks in Serverless Functions` (High)**
  - *Pattern:* New `new Redis()` created on every API invocation without caching client instance in `globalThis`.
  - *Remediation:* Implement singleton client pattern with connection reuse across warm function containers.

### 3.4 SQLite & Local / Embedded Databases
- **`SQLITE-SEC-01: Publicly Exposed or World-Readable SQLite Database File` (Critical)**
  - *Pattern:* `.sqlite`, `.sqlite3`, `.db` files located inside `public/`, `static/`, or `www/` folders, or initialized with permissions `0666`.
  - *Remediation:* Relocate database file outside public root; enforce strict file permissions (`chmod 0600`) and configure web server rules to deny `.db*` downloads.
- **`SQLITE-SEC-02: Unencrypted Sensitive Data at Rest (Mobile / Desktop)` (High)**
  - *Pattern:* Storing authentication tokens, PII, or credentials in standard SQLite without encryption on client devices.
  - *Remediation:* Integrate SQLCipher or platform-native encrypted vaults (iOS Keychain / Android Keystore + Encrypted Room).
- **`SQLITE-PERF-03: Missing WAL Mode & Concurrency Lock Contention` (Medium)**
  - *Pattern:* SQLite initialized without Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) leading to `SQLITE_BUSY` database lock errors under concurrent read/write loads.
  - *Remediation:* Execute `PRAGMA journal_mode = WAL;` and `PRAGMA busy_timeout = 5000;` on connection open.

### 3.5 ORMs & Query Builders (Prisma, TypeORM, Drizzle, SQLAlchemy, GORM)
- **`ORM-RAW-01: Prisma $queryRawUnsafe SQL Injection` (Critical)**
  - *Pattern:* Calling `prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)`.
  - *Remediation:* Migrate to type-safe parameterized tagged template: `prisma.$queryRaw\`SELECT * FROM users WHERE email = ${email}\``.
- **`ORM-RAW-02: TypeORM & Sequelize Raw Query Escaping Bypass` (Critical)**
  - *Pattern:* `dataSource.query("SELECT * FROM products WHERE category = '" + cat + "'")`.
  - *Remediation:* Pass parameters via array binding: `dataSource.query('SELECT * FROM products WHERE category = $1', [cat])`.
- **`ORM-MIG-03: Destructive Zero-Downtime Migration Failure` (High)**
  - *Pattern:* Migration files containing `ALTER TABLE ... DROP COLUMN` or table rename without expand-and-contract pattern.
  - *Remediation:* Enforce 2-phase deployment: Deprecate column in application code -> Deploy -> Drop column in subsequent migration.
- **`ORM-PERF-04: N+1 Iteration Query Trap` (High)**
  - *Pattern:* Performing queries inside `array.map(async item => { await orm.query(...) })` or `for (item of items)`.
  - *Remediation:* Batch query using `IN` filters or ORM relation joins (`include`, `relations`, `joinedload`, `Preload`).

---

## 4. Product & UI Positioning Strategy

To communicate Zelsis's universal polyglot capabilities effectively, the user experience across landing pages, scan configuration, and findings management will be enhanced:

### 4.1 UI/UX Architecture Adjustments

```
+----------------------------------------------------------------------------------------------------+
|                                    ZELSIS SCAN CONFIGURATION                                       |
+----------------------------------------------------------------------------------------------------+
| Target: https://github.com/acme-corp/fintech-backend                                               |
|                                                                                                    |
| Detected Stack: [ TypeScript ] [ Go ] [ Python ]                                                   |
| Detected Storage: [ MySQL 8.0 ] [ Redis 7.2 ] [ DynamoDB ] [ Pinecone Vector ]                     |
|                                                                                                    |
| PRESETS:                                                                                           |
| (•) Full Polyglot Enterprise Gate (SQL + NoSQL + Cache + Vector)                                    |
| ( ) Relational Deep-Audit (PostgreSQL, MySQL, MariaDB, MSSQL, Oracle)                              |
| ( ) AI & Vector Readiness Gate (pgvector, Pinecone, Qdrant, Weaviate)                              |
| ( ) High-Throughput Cache & NoSQL (Redis, Dragonfly, MongoDB, DynamoDB)                            |
| ( ) Embedded & Mobile Store Gate (SQLite, Room, Realm)                                             |
+----------------------------------------------------------------------------------------------------+
```

1. **Scan Runner — Auto-Detection Badges:**
   - When a repository is analyzed, Zelsis scans package manifests (`package.json`, `go.mod`, `requirements.txt`, `pom.xml`, `Gemfile`, `Cargo.toml`, `docker-compose.yml`).
   - Badges dynamically appear: `[PostgreSQL]`, `[MySQL]`, `[MongoDB]`, `[Redis]`, `[Elasticsearch]`, `[Pinecone]`, `[SQLite]`.
2. **Scan Runner Presets:**
   - Add specialized audit presets tailored to modern architectures:
     - **Polyglot Enterprise Gate:** Complete coverage across all relational, NoSQL, memory, and vector tiers.
     - **Relational & SQL Hardening:** Deep query optimization, SQLi, migration validation, indexing.
     - **AI / RAG Infrastructure Gate:** Vector database security, dimensionality verification, latency SLAs.
     - **NoSQL & Cloud Document Gate:** MongoDB, DynamoDB, Firestore rules, access controls.
     - **Cache & Real-Time Performance:** Redis / Memcached eviction safety, Lua script review, connection reuse.
3. **Findings Matrix & Filtering:**
   - Add a dedicated **Storage Paradigm** selector to the Findings Table:
     `[ All (42) ] [ Relational SQL (18) ] [ NoSQL (9) ] [ Cache/Redis (8) ] [ Vector (7) ]`
   - Include **Driver / ORM Tags**:
     `[Prisma]`, `[Drizzle]`, `[Mongoose]`, `[SQLAlchemy]`, `[GORM]`, `[Redis-py]`, `[Native]`.
   - Provide multi-language remediation snippets with tabbed toggle:
     `[ TypeScript / Node.js ] [ Python ] [ Go ] [ Java ] [ Raw SQL ]`.

---

## 5. Implementation Roadmap

| Phase | Milestone | Deliverables | Timeline |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Multi-DB AST Parser Integration** | Finalize rule definitions for MySQL, Mongo, Redis, SQLite, MSSQL, Oracle, DynamoDB, and Vector stores in `lib/rules/`. | Week 1 |
| **Phase 2** | **Manifest & Docker Auto-Detection** | Enhance repository analyzer to detect all installed database drivers, ORMs, and `docker-compose` services automatically. | Week 2 |
| **Phase 3** | **UI Preset & Filtering Update** | Update `ScanRunnerView.tsx` and `FindingsTable.tsx` with storage paradigm filters, driver badges, and polyglot remediation tabs. | Week 3 |
| **Phase 4** | **Test Suite & Benchmarking** | Implement comprehensive test suite in `tests/test_suite.ts` verifying detection accuracy against polyglot database repos. | Week 4 |

---

*Authored by the Lead Database Architect for Zelsis SaaS.*
