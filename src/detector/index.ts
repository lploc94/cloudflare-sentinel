/**
 * Detector exports
 * Base classes and interfaces for building custom detectors
 */

// Export base detector interfaces and classes
export { BaseDetector, type IDetector, type DetectorResult, type DetectionEvidence } from './base';

// Request detectors
export { SQLInjectionRequestDetector } from './sql-injection.request.detector';
export { XSSRequestDetector } from './xss.request.detector';
export { PathTraversalRequestDetector } from './path-traversal.request.detector';

// Response detectors
export { SQLInjectionResponseDetector } from './sql-injection.response.detector';
export { XSSResponseDetector } from './xss.response.detector';
export { PathTraversalResponseDetector } from './path-traversal.response.detector';

// Behavior detector (works on both request + response)
export { BruteForceDetector } from './brute-force.detector';

// Entropy-based detector
export { EntropyDetector, type EntropyDetectorConfig } from './entropy.detector';

// Export examples (user can reference)
export * from './custom-example';
