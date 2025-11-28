# Cloudflare Sentinel - Detector Reference

Complete list of all detectors in the `cloudflare-sentinel` package.

## Overview

| Category | Count | Detectors |
|----------|-------|-----------|
| Access Control | 2 | BlocklistDetector, RateLimitDetector |
| Injection | 5 | SQLInjection, XSS, NoSQL, CommandInjection, SSTI |
| Protocol | 4 | CSRF, XXE, HTTPSmuggling, JWT |
| Redirect | 2 | OpenRedirect, SSRF |
| Path | 1 | PathTraversal |
| Response | 3 | SQLInjection, XSS, PathTraversal (leak detection) |
| Behavior | 3 | BruteForce, FailureThreshold, Entropy |
| **Total** | **21** | |

---

## Detector List

### Access Control

| Detector | Purpose | When to Use | Config |
|----------|---------|-------------|--------|
| **BlocklistDetector** | Block requests from IPs or keys stored in KV blocklist | **All endpoints** - Block known attackers, banned users, malicious IPs. Use after incident response to prevent repeat attacks. Essential for production. | `kv: KVNamespace` |
| **RateLimitDetector** | Limit request rate per IP or custom key | **API endpoints** - Prevent abuse, DoS. **Login endpoints** - Slow down brute force. **Public endpoints** - Enforce fair usage. **Webhook receivers** - Prevent flood. | `limit`, `period`, `kv` or CF API |

### Injection Attacks (Request)

| Detector | Purpose | When to Use | Severity |
|----------|---------|-------------|----------|
| **SQLInjectionRequestDetector** | Detect SQL injection patterns in queries, body, headers | **Endpoints querying SQL database** (MySQL, PostgreSQL, SQLite, MSSQL). Examples: `/search`, `/login`, `/users/:id`, `/reports`. Any endpoint accepting user input that builds SQL queries. | HIGH-CRITICAL |
| **XSSRequestDetector** | Detect XSS payloads (script tags, event handlers, javascript:) | **Endpoints reflecting user input** - `/search?q=`, `/profile`, `/comments`. **Form submission endpoints**. **Error handlers** that echo input. Any endpoint where input may appear in HTML response. | HIGH |
| **NoSQLInjectionDetector** | Detect NoSQL injection (MongoDB operators, JSON injection) | **Endpoints querying NoSQL databases** (MongoDB, CouchDB, DynamoDB, Redis). Examples: `/api/users`, `/api/products?filter=`. JSON body endpoints with complex queries. | HIGH-CRITICAL |
| **CommandInjectionDetector** | Detect OS command injection (shell metacharacters, common commands) | **Endpoints executing shell commands** - `/convert`, `/export`, `/resize`, `/ping`. File processing endpoints, PDF generators, image converters. Any endpoint calling exec/spawn/system. | CRITICAL |
| **SSTIDetector** | Detect Server-Side Template Injection leading to RCE | **Endpoints with template rendering** - `/preview`, `/render`, `/email/send`. CMS endpoints, report generators, email template endpoints. Jinja2, Twig, ERB, Freemarker, Thymeleaf, etc. | CRITICAL (RCE) |

### Protocol Attacks

| Detector | Purpose | When to Use | Severity |
|----------|---------|-------------|----------|
| **CSRFDetector** | Validate Origin/Referer headers for cross-origin protection | **State-changing endpoints** (POST, PUT, DELETE). Examples: `/api/users`, `/api/settings`, `/api/transfer`. Form submissions, profile updates, payment endpoints, any mutating operation. | HIGH |
| **XXEDetector** | Detect XML External Entity injection | **Endpoints accepting XML** - SOAP endpoints, `/upload` (XML/SVG), `/import`, RSS feed processors. Office doc handlers (DOCX, XLSX), config file uploads, any XML parsing endpoint. | CRITICAL |
| **HTTPSmugglingDetector** | Detect HTTP request smuggling (CL.TE conflicts, header injection) | **All endpoints** - Defense in depth. Especially important for endpoints behind reverse proxies, load balancers, or multi-tier architectures. Cloudflare handles most, this adds extra protection. | CRITICAL |
| **JWTDetector** | Detect JWT attacks (alg=none, kid injection, jku SSRF) | **JWT-protected endpoints** - Any endpoint using `Authorization: Bearer <JWT>`. OAuth callbacks, API endpoints, SSO endpoints. Microservice-to-microservice auth endpoints. | CRITICAL |

### Redirect Attacks

| Detector | Purpose | When to Use | Severity |
|----------|---------|-------------|----------|
| **OpenRedirectDetector** | Detect malicious redirect URLs in parameters | **Endpoints with redirect params** - `/login?return_url=`, `/logout?redirect=`, `/oauth/callback?redirect_uri=`. Link shortener endpoints, email tracking endpoints, any `?url=`, `?next=`, `?goto=` params. | HIGH |
| **SSRFDetector** | Detect Server-Side Request Forgery attempts | **Endpoints fetching external URLs** - `/preview?url=`, `/webhook`, `/import?source=`, `/proxy`. PDF generators, image fetchers, URL validators. Any endpoint making outbound requests from user input. | CRITICAL |

### Path Attacks

| Detector | Purpose | When to Use | Severity |
|----------|---------|-------------|----------|
| **PathTraversalRequestDetector** | Detect path traversal (../, encoded variants) in requests | **File-serving endpoints** - `/download?file=`, `/assets/:path`, `/template?name=`. Static file servers, theme selectors, document viewers. Any endpoint with filename/path parameter. | HIGH-CRITICAL |
| **PathTraversalResponseDetector** | Detect sensitive file content leaks in response | **Response analysis for file endpoints** - Detect /etc/passwd, Windows system files, config files in response body. Use with response pipeline to catch leaks. | CRITICAL |

### Response Leak Detection

| Detector | Purpose | When to Use | Severity |
|----------|---------|-------------|----------|
| **SQLInjectionResponseDetector** | Detect SQL error messages in response | **All endpoints (response phase)** - Catch exposed SQL errors like "MySQL syntax error", stack traces. Development endpoints, staging environments. Compliance: prevent DB schema exposure. | MEDIUM-HIGH |
| **XSSResponseDetector** | Detect reflected XSS in response | **Endpoints echoing user input** - Validate output encoding. Check if XSS payloads pass through to response body. Response sanitization validation. | HIGH |
| **PathTraversalResponseDetector** | Detect sensitive file contents in response | **File-serving endpoints (response phase)** - Validate path traversal blocks are working. Catch accidental file exposure, detect successful traversal attacks. | CRITICAL |

### Behavior Analysis

| Detector | Purpose | When to Use | Severity |
|----------|---------|-------------|----------|
| **BruteForceDetector** | Count authentication failures per IP with KV storage | **Auth endpoints** - `/login`, `/signin`, `/auth`, `/api/auth`. **Reset endpoints** - `/forgot-password`, `/verify-code`. **2FA endpoints** - `/verify-otp`. Any endpoint validating credentials. | HIGH |
| **FailureThresholdDetector** | Generic failure counting for any status codes | **Custom rate-limit scenarios** - Count 4xx/5xx per IP. **Enumeration detection** - Too many 404s on `/users/:id`. **Error spike detection**. Base class for custom failure-based detectors. | Configurable |
| **EntropyDetector** | Detect high-entropy strings (encoded/encrypted payloads) | **All endpoints (supplementary)** - Detect Base64/encoded attack payloads. Catch obfuscated injections bypassing pattern detection. Useful for endpoints accepting arbitrary strings. | MEDIUM |

---

## Usage Recommendations

### For API Backend

```typescript
const pipeline = SentinelPipeline.sync([
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new RateLimitDetector({ limit: 100, period: 60 }),
  new SQLInjectionRequestDetector(),
  new NoSQLInjectionDetector(),
  new CommandInjectionDetector(),
  new JWTDetector(),
]);
```

### For Web App with Forms

```typescript
const pipeline = SentinelPipeline.sync([
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new CSRFDetector({ mode: 'strict' }),
  new XSSRequestDetector(),
  new SQLInjectionRequestDetector(),
  new OpenRedirectDetector(),
]);
```

### For File Upload/Download

```typescript
const pipeline = SentinelPipeline.sync([
  new PathTraversalRequestDetector(),
  new XXEDetector({ contentTypes: ['*'] }),
  new CommandInjectionDetector(),
]);
```

### For Auth Endpoints

```typescript
const pipeline = SentinelPipeline.sync([
  new RateLimitDetector({ limit: 10, period: 60 }),
  new BruteForceDetector({ kv: env.BRUTE_FORCE_KV, threshold: 5 }),
  new SQLInjectionRequestDetector(),
]);
```

### Full Protection (All Detectors)

```typescript
const pipeline = SentinelPipeline.sync([
  // Access Control
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new RateLimitDetector({ limit: 100, period: 60 }),
  
  // Injection
  new SQLInjectionRequestDetector(),
  new XSSRequestDetector(),
  new NoSQLInjectionDetector(),
  new CommandInjectionDetector(),
  new SSTIDetector(),
  
  // Protocol
  new CSRFDetector(),
  new XXEDetector(),
  new HTTPSmugglingDetector(),
  new JWTDetector(),
  
  // Redirect
  new OpenRedirectDetector(),
  new SSRFDetector(),
  
  // Path
  new PathTraversalRequestDetector(),
]);
```

---

## Detector Priorities

Execution order (priority DESC, higher runs first):

| Priority | Detector | Reason |
|----------|----------|--------|
| 100 | BlocklistDetector | Block known bad actors immediately |
| 98 | HTTPSmugglingDetector | Check protocol-level attacks early |
| 95 | RateLimitDetector | Prevent flood before processing |
| 92 | SSTIDetector | Remote Code Execution risk |
| 90 | CSRFDetector, XXEDetector, SQLInjection | High severity attacks |
| 88 | JWTDetector | Authentication bypass attacks |
| 85 | OpenRedirectDetector, CommandInjection | Medium-high severity |
| 80 | XSSDetector, PathTraversal | Common web attacks |
| 70 | NoSQLInjection, SSRF | Specific use cases |
| 60 | EntropyDetector | Supplementary detection |

---

## Test Coverage

| Detector | Tests |
|----------|-------|
| SQLInjectionRequestDetector | 12 |
| XSSRequestDetector | 19 |
| PathTraversalDetector | 23 |
| CommandInjectionDetector | 12 |
| NoSQLInjectionDetector | 14 |
| SSRFDetector | 17 |
| BlocklistDetector | 11 |
| RateLimitDetector | 21 |
| BruteForceDetector | 20 |
| EntropyDetector | 9 |
| CSRFDetector | 26 |
| XXEDetector | 28 |
| OpenRedirectDetector | 28 |
| HTTPSmugglingDetector | 33 |
| JWTDetector | 26 |
| SSTIDetector | 30 |
| **Total** | **364** |

---

## OWASP Top 10 Coverage

| OWASP 2021 | Detectors |
|------------|-----------|
| A01 Broken Access Control | BlocklistDetector, RateLimitDetector, CSRFDetector |
| A02 Cryptographic Failures | JWTDetector (weak alg) |
| A03 Injection | SQLInjection, XSS, NoSQL, CommandInjection, SSTI, XXE |
| A04 Insecure Design | - (design level, not WAF) |
| A05 Security Misconfiguration | HTTPSmugglingDetector |
| A06 Vulnerable Components | - (not WAF scope) |
| A07 Auth Failures | BruteForceDetector, JWTDetector |
| A08 Software/Data Integrity | - (not WAF scope) |
| A09 Logging Failures | - (handled by handlers) |
| A10 SSRF | SSRFDetector, OpenRedirectDetector |

---

*Last updated: November 2025*
