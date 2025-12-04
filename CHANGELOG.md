# Changelog

All notable changes to Cloudflare Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.0-beta.2] - 2025-12-04

### Changed
- **PipelineContext** now includes common request info fields for easier handler access:
  - `clientIp`: Client IP address (from CF-Connecting-IP)
  - `path`: Request path
  - `method`: Request method (GET, POST, etc.)
  - `userAgent`: User agent string
  - `metadata`: Generic extension point for app-specific data (userId, CF colo, etc.)

### Removed
- `userId` from PipelineContext - moved to `metadata` (app-specific)

### Migration
```typescript
// Before - handlers had to extract IP from request or evidence
const ip = ctx.request?.headers.get('cf-connecting-ip');

// After - direct access from context
const ip = ctx.clientIp;
const userId = ctx.metadata?.userId; // app-specific, in metadata
```

## [2.3.0-beta.1] - 2025-12-03

### Changed
- **BREAKING**: Unified `BlocklistDetector` with `mode` option (`'direct'` | `'cuckoo'`)
- **BREAKING**: Unified `BlocklistHandler` with `mode` option (`'direct'` | `'cuckoo'`)

### Removed
- `CuckooBlocklistDetector` - Use `BlocklistDetector({ mode: 'cuckoo' })`
- `CuckooBlocklistHandler` - Use `BlocklistHandler({ mode: 'cuckoo' })`

### Added
- `BlocklistDetector` mode options:
  - `'direct'`: Simple KV read per request (default)
  - `'cuckoo'`: Cache API + Cuckoo Filter + KV verify
- `BlocklistHandler` mode options:
  - `'direct'`: KV-only writes (default)
  - `'cuckoo'`: Pending Cache + KV + Queue sync
- Queue helpers: `sendBlockToQueue()`, `sendUnblockToQueue()`, `processBlocklistQueue()`, `rebuildBlocklistFilter()`, `getBlocklistStats()`
- `CuckooFilter` utility for probabilistic data structure

### Migration
```typescript
// Before
new CuckooBlocklistDetector({ kv });
new CuckooBlocklistHandler({ queue });

// After  
new BlocklistDetector({ kv, mode: 'cuckoo' });
new BlocklistHandler({ kv, mode: 'cuckoo', queue });
```

## [2.2.0] - 2025-11-29

### Added
- **MLDetector `excludeFields` option** - Exclude token fields from ML analysis to avoid false positives
  - Example: `excludeFields: ['token', 'google_token', 'refresh_token']`

### Changed
- **Default `excludeFields` for all body-analyzing detectors**
  - Added token-related defaults: `['token', 'access_token', 'refresh_token', 'google_token', 'id_token', 'jwt', 'password', 'secret']`
  - Affected detectors: SQLInjectionRequestDetector, XSSRequestDetector, SSTIDetector, SSRFDetector, XXEDetector, MLDetector
  - Reduces false positives when scanning JSON APIs with token-based authentication

## [2.1.1] - 2025-11-29

### Fixed
- **Package exports** - Fixed outdated exports in package.json
  - Removed non-existent `./middleware` and `./logger` exports
  - Added new subpath exports: `./pipeline`, `./scoring`, `./resolver`, `./handler`, `./ml`, `./utils`
- **Clean build** - Removed legacy folders from dist/

## [2.1.0] - 2025-11-29

### Added
- **AnalyticsHandler** - New handler for Cloudflare Analytics Engine logging
  - Configurable source, category, and index extraction
  - Full evidence serialization support
- **IP Extraction Utilities** - `extractIP()` and `extractIPFromContext()` helpers
  - Supports CF-Connecting-IP, X-Real-IP, X-Forwarded-For headers
- **Comprehensive Test Suite** - 609 tests covering all components
  - Handler tests: LogHandler, NotifyHandler, BlocklistHandler, ReputationHandler, AnalyticsHandler
  - Scoring tests: MaxScoreAggregator, WeightedAggregator
  - Resolver tests: DefaultResolver, StrictResolver, LenientResolver, MultiLevelResolver
  - Pipeline tests: SentinelPipeline, Decision
  - ML tests: HashingVectorizer, LinearClassifier

### Changed
- **LogHandler** - Removed `analytics` option (use AnalyticsHandler instead)
- **Documentation** - Comprehensive JSDoc for all modules
  - Scoring: Severity/level tables, aggregator comparisons
  - Resolver: Threshold behaviors, use case recommendations
  - Pipeline: Architecture diagrams, sync/async examples
  - ML: sklearn compatibility notes, algorithm explanations
- **Getting Started** - Updated with ActionType enum, ReputationDetector examples
- **Notifications** - Fixed examples to use ActionType enum

### Fixed
- **sentinel-proxy example** - Fixed non-existent handler imports
  - Replaced IncrementHandler, EscalateHandler, BanHandler with actual handlers
  - Updated to use ActionType enum instead of strings
- **Threshold configurations** - Consistent ActionType usage across all examples

## [2.0.1] - 2025-11-29

### Changed
- **Detector Confidence = 1.0** - All fact-based detectors now use confidence = 1.0
  - `FailureThresholdDetector`: baseConfidence changed from 0.5 to 1.0 (failure count is exact, not a guess)
  - `ReputationDetector`: confidence changed from 0.95/0.6 to 1.0 (reputation score is calculated fact)
  - This affects score calculation: score = severity × confidence (now severity × 1.0)

### Added
- **MultiLevelResolver UPDATE_REPUTATION support** - Can now include `ActionType.UPDATE_REPUTATION` in level actions
- **BaseActionResolver.updateReputation()** - New helper method for creating update_reputation actions

### Fixed
- `FailureThresholdDetector` test cases updated to reflect confidence = 1.0 behavior

## [2.0.0] - 2025-11-28

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
