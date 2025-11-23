/**
 * Brute Force Detector
 * Detects brute force attacks on authentication endpoints
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class BruteForceDetector extends BaseDetector {
  name = 'brute-force';
  priority = 85;

  private readonly authEndpoints = [
    /\/login/i,
    /\/signin/i,
    /\/auth/i,
    /\/authenticate/i,
    /\/session/i,
    /\/token/i,
    /\/oauth/i,
    /\/sso/i,
    /\/api\/auth/i,
    /\/admin\/login/i,
  ];

  private readonly suspiciousPatterns = [
    // Multiple failed attempts indicators in response
    { regex: /invalid\s+(password|credentials|login)/i, confidence: 0.8 },
    { regex: /authentication\s+failed/i, confidence: 0.8 },
    { regex: /incorrect\s+(password|username)/i, confidence: 0.8 },
    { regex: /access\s+denied/i, confidence: 0.6 },
    { regex: /unauthorized/i, confidence: 0.5 },
  ];

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Only check POST requests to auth endpoints
    if (request.method !== 'POST') {
      return null;
    }

    // Check if this is an authentication endpoint
    const isAuthEndpoint = this.authEndpoints.some(pattern => pattern.test(url.pathname));
    
    if (!isAuthEndpoint) {
      return null;
    }

    // Check for suspicious patterns in request body
    try {
      const contentType = request.headers.get('content-type') || '';
      
      if (contentType.includes('application/json') || contentType.includes('application/x-www-form-urlencoded')) {
        const body = await request.clone().text();
        
        // Check for automated tool signatures
        const automatedToolDetection = this.detectAutomatedTools(request, body);
        if (automatedToolDetection) {
          return automatedToolDetection;
        }

        // Check for credential stuffing patterns
        const credentialStuffing = this.detectCredentialStuffing(body, url.pathname);
        if (credentialStuffing) {
          return credentialStuffing;
        }
      }
    } catch (error) {
      // Cannot read body, skip
    }

    // Basic detection - flag auth requests for behavior tracking
    // The actual brute force will be detected by BehaviorTracker based on failure rate
    return this.createResult(
      AttackType.BRUTE_FORCE,
      SecuritySeverity.LOW,
      0.5,
      {
        field: 'endpoint',
        value: url.pathname,
      },
      {
        reason: 'auth_endpoint_access',
        method: request.method,
      }
    );
  }

  async detectResponse(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check if this is an auth endpoint with failed response
    const isAuthEndpoint = this.authEndpoints.some(pattern => pattern.test(url.pathname));
    
    if (!isAuthEndpoint || response.status < 400) {
      return null;
    }

    // Higher confidence if we see multiple failed attempts in short time
    // This will be combined with BehaviorTracker data
    let confidence = 0.6;
    
    if (response.status === 401 || response.status === 403) {
      confidence = 0.7;
    }

    // Try to read response body for error messages
    try {
      const responseText = await response.clone().text();
      
      for (const { regex, confidence: patternConf } of this.suspiciousPatterns) {
        if (regex.test(responseText)) {
          confidence = Math.max(confidence, patternConf);
          break;
        }
      }
    } catch {
      // Cannot read response body
    }

    return this.createResult(
      AttackType.BRUTE_FORCE,
      this.getSeverity(confidence, response.status),
      confidence,
      {
        field: 'response',
        value: `${response.status}`,
      },
      {
        statusCode: response.status,
        endpoint: url.pathname,
      }
    );
  }

  private detectAutomatedTools(request: Request, body: string): DetectorResult | null {
    const userAgent = request.headers.get('user-agent') || '';
    
    // Common pentesting/brute force tool signatures
    const toolSignatures = [
      /hydra/i,
      /burp/i,
      /nikto/i,
      /sqlmap/i,
      /nmap/i,
      /masscan/i,
      /zap/i,
      /metasploit/i,
      /wfuzz/i,
      /dirbuster/i,
      /gobuster/i,
    ];

    for (const signature of toolSignatures) {
      if (signature.test(userAgent) || signature.test(body)) {
        return this.createResult(
          AttackType.BRUTE_FORCE,
          SecuritySeverity.HIGH,
          0.95,
          {
            field: 'user_agent',
            value: userAgent.substring(0, 50),
          },
          {
            reason: 'automated_tool_detected',
          }
        );
      }
    }

    return null;
  }

  private detectCredentialStuffing(body: string, endpoint: string): DetectorResult | null {
    // Credential stuffing often uses email:password format
    const emailPasswordPattern = /[\w.-]+@[\w.-]+:\S+/;
    
    if (emailPasswordPattern.test(body)) {
      return this.createResult(
        AttackType.CREDENTIAL_STUFFING,
        SecuritySeverity.HIGH,
        0.9,
        {
          field: 'body',
          value: 'credential_pair_detected',
        },
        {
          reason: 'credential_stuffing_pattern',
          endpoint,
        }
      );
    }

    return null;
  }

  private getSeverity(confidence: number, statusCode: number): SecuritySeverity {
    // Failed auth attempts are more severe
    if (statusCode === 401 || statusCode === 403) {
      if (confidence >= 0.8) return SecuritySeverity.HIGH;
      if (confidence >= 0.6) return SecuritySeverity.MEDIUM;
    }
    
    if (confidence >= 0.9) return SecuritySeverity.HIGH;
    if (confidence >= 0.7) return SecuritySeverity.MEDIUM;
    return SecuritySeverity.LOW;
  }
}
