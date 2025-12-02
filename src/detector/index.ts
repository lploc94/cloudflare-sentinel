/**
 * Detector exports
 */

// Base
export { 
  BaseDetector, 
  type IDetector, 
  type DetectorResult, 
  type DetectionEvidence,
  type DetectorPhase,
  type BaseDetectorOptions,
} from './base';

// Security detectors
export { BlocklistDetector, type BlocklistDetectorOptions } from './blocklist.detector';
export { CuckooBlocklistDetector, type CuckooBlocklistDetectorOptions } from './cuckoo-blocklist.detector';
export { RateLimitDetector, type RateLimitDetectorConfig, type CloudflareRateLimitConfig, type KVRateLimitConfig, type RateLimiter } from './rate-limit.detector';
export { ReputationDetector, type ReputationDetectorOptions } from './reputation.detector';

// Request detectors
export { SQLInjectionRequestDetector, type SQLInjectionRequestDetectorConfig, type SQLInjectionPattern, type SQLInjectionSanitizer } from './sql-injection.request.detector';
export { XSSRequestDetector, type XSSRequestDetectorConfig, type XSSPattern } from './xss.request.detector';
export { PathTraversalRequestDetector, type PathTraversalRequestDetectorConfig, type PathTraversalPattern } from './path-traversal.request.detector';

// Response detectors
export { SQLInjectionResponseDetector, type SQLInjectionResponseDetectorConfig, type SQLLeakPattern, type EvidenceSanitizer } from './sql-injection.response.detector';
export { XSSResponseDetector } from './xss.response.detector';
export { PathTraversalResponseDetector, type PathTraversalResponseDetectorConfig, type ResponseLeakPattern } from './path-traversal.response.detector';

// Behavior detectors
export { FailureThresholdDetector, FailureStatusPresets, type FailureThresholdDetectorOptions } from './failure-threshold.detector';
export { BruteForceDetector, type BruteForceDetectorOptions } from './brute-force.detector';
export { EntropyDetector, type EntropyDetectorConfig } from './entropy.detector';

// Injection detectors
export { CommandInjectionDetector, type CommandInjectionDetectorConfig, type CommandPattern } from './command-injection.detector';
export { SSRFDetector, type SSRFDetectorConfig, type CloudMetadataPattern, type SSRFBypassPattern } from './ssrf.detector';
export { NoSQLInjectionDetector, type NoSQLInjectionDetectorConfig, type NoSQLPattern } from './nosql-injection.detector';
export { CSRFDetector, type CSRFDetectorConfig } from './csrf.detector';
export { XXEDetector, type XXEDetectorConfig, type XXEPattern } from './xxe.detector';
export { OpenRedirectDetector, type OpenRedirectDetectorConfig } from './open-redirect.detector';
export { HTTPSmugglingDetector, type HTTPSmugglingDetectorConfig } from './http-smuggling.detector';
export { JWTDetector, type JWTDetectorConfig } from './jwt.detector';
export { SSTIDetector, type SSTIDetectorConfig, type SSTIPattern } from './ssti.detector';

// ML-based detector
export { MLDetector, type MLDetectorOptions } from './ml.detector';

// Examples (reference only)
export * from './_examples';
