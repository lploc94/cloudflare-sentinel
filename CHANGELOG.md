# Changelog

All notable changes to Cloudflare Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Pipeline Architecture** - New `SentinelPipeline` class with composable stages
  - `SentinelPipeline.sync()` - Returns Decision, user controls response
  - `SentinelPipeline.async()` - Fire-and-forget background processing
- **Multi-Level Resolver** - `MultiLevelResolver` with configurable thresholds and cascading actions
- **MLDetector** - Lightweight ML classifier for suspicious request pre-filtering
  - Binary classification: safe vs suspicious
  - ~224KB bundled model trained on 133K samples
  - Custom model support via options
- **ML Training Scripts** (`scripts/training/`)
  - `download_datasets.py` - Download PayloadsAllTheThings + SecLists
  - `generate_safe_requests.py` - Generate synthetic safe requests
  - `train_classifier.py` - Train scikit-learn classifier
- **New Detectors**
  - `BlocklistDetector` - IP blocklist (KV-based)
  - `RateLimitDetector` - Rate limiting (KV-based)
  - `ReputationDetector` - IP reputation scoring
  - `XXEDetector` - XML External Entity injection
  - `SSTIDetector` - Server-Side Template Injection
  - `JWTDetector` - JWT attacks (alg=none, kid injection)
  - `HTTPSmugglingDetector` - HTTP Request Smuggling
  - `OpenRedirectDetector` - Open redirect vulnerabilities
  - `CSRFDetector` - Cross-Site Request Forgery
- **New Handlers**
  - `BlocklistHandler` - Add to KV blocklist
  - `ReputationHandler` - Update IP reputation score
- **ML Module** (`src/ml/`) - MurmurHash3, HashingVectorizer, LinearClassifier
- **Response Detection** - Process responses for data leak detection
- **Route-Based Config** - Different protection levels per endpoint

### Changed
- **Breaking**: Replaced `Sentinel` class with `SentinelPipeline`
- **Breaking**: Replaced `attackLimits` with `MultiLevelResolver` thresholds
- Flattened source structure - removed nested folders

### Removed
- Old `Sentinel` class and `protect()` method
- `attackLimits` configuration
- D1 database dependency (now optional)
- Removed unused components: `WhitelistDetector`, `DataLeakDetector`, `ErrorLeakDetector`, `BanHandler`, `IncrementHandler`, `EscalateHandler`, `HybridAggregator`

### Documentation
- Sync all docs with actual codebase
- Fix license text (Cloudflare Only License)
- Update code examples with correct component names
- Add `engines` field to package.json (Node >=18)

## [1.0.4] - 2025-11-25

### Added
- **Unified detectors configuration** - Merge global and endpoint-specific detectors into single field
  - Array format: `detectors: [new SQLInjectionRequestDetector()]` (backward compatible)
  - Object format: `detectors: { '*': [global], '/api/*': [endpoint-specific] }`
  - Mirrors `attackLimits` configuration pattern for consistency
  - Warning when endpoint patterns exist but no global detectors configured
  - See [Detector Guide](docs/detectors.md#endpoint-specific-detectors) for examples

## [1.0.3] - 2025-11-25

### Added
- **Endpoint-specific detectors** - Apply detectors only to specific endpoints
  - Global detectors run on all endpoints
  - Endpoint-specific detectors run only on matching paths
  - Supports glob patterns: `*`, `**`, `?`
  - See [Detector Guide](docs/detectors.md#endpoint-specific-detectors) for examples

## [1.0.2] - 2025-11-25

### Added
- **Shannon Entropy Detector** - Detects obfuscated/encoded payloads
  - Catches base64, hex, and other encoded attack payloads
  - Complements pattern-based detectors
  - Configurable entropy threshold, path/field exclusions
  - See [Detector Guide](docs/detectors.md#shannon-entropy-detector) for use cases
- `OBFUSCATED_PAYLOAD` attack type

## [1.0.1] - 2025-11-25

### Added
- `RateLimitPeriod` enum for type-safe rate limiting configuration
- Comprehensive use cases documentation
- Detailed limitations section
- Full contributing guide for developers
- Cost estimation with accurate pricing tiers
- Performance impact documentation

### Changed
- Updated cost estimates with real-world numbers ($0-11/month)
- Improved README structure with better organization
- Enhanced examples with more use cases
- Rate limit periods now use `RateLimitPeriod` enum for better type safety
  - `RateLimitPeriod.TEN_SECONDS` (10s) - for burst protection
  - `RateLimitPeriod.ONE_MINUTE` (60s) - for sustained rate limiting
  - Enforces Cloudflare Rate Limiting API constraints at compile-time
  - Updated all documentation and examples

### Fixed
- Corrected pricing information in README
- Fixed Cloudflare Rate Limiting API usage - custom periods would fail at runtime, now caught at compile-time

## [1.0.0] - Initial Release

### Added
- Core Sentinel middleware with pluggable detector system
- Attack-based rate limiting (not just endpoint-based)
- Layered rate limiting (global + endpoint-scoped)
- Built-in detectors:
  - SQL Injection (request + response)
  - XSS (request + response)
  - Path Traversal (request + response)
  - Brute Force
- Behavior tracking for logic-based attacks
- Smart logging (errors/attacks only)
- Analytics Engine integration
- D1 Database logging (critical events)
- KV-based behavior tracking
- Cloudflare Rate Limiting API integration
- Early block check optimization
- Sentinel Proxy example for legacy websites
- Comprehensive documentation
- TypeScript support
- Unit tests for core functionality

### Security
- Rate limiting to prevent brute force
- SQL injection detection with pattern matching
- XSS detection (request and response)
- Path traversal detection
- Behavior-based attack detection
- Attack evidence logging

### Performance
- Optimized flow with early block check
- Smart logging (95% reduction in operations)
- KV caching for rate limit checks
- Parallel rate limit checking support
- Minimal overhead (~1-5ms per request)

---

## Version Format

- **Major.Minor.Patch** (e.g., 1.2.3)
  - **Major**: Breaking changes
  - **Minor**: New features (backward compatible)
  - **Patch**: Bug fixes (backward compatible)

## Categories

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security improvements

---

[Unreleased]: https://github.com/lploc94/cloudflare-sentinel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/lploc94/cloudflare-sentinel/releases/tag/v1.0.0
