# Changelog

All notable changes to Cloudflare Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive use cases documentation
- Detailed limitations section
- Full contributing guide for developers
- Cost estimation with accurate pricing tiers
- Performance impact documentation

### Changed
- Updated cost estimates with real-world numbers ($0-11/month)
- Improved README structure with better organization
- Enhanced examples with more use cases

### Fixed
- Corrected pricing information in README

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
