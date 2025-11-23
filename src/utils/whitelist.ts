/**
 * Whitelist management for bypassing security checks
 * Supports IPs, IP ranges (CIDR), and user IDs
 */

import { isIpInCidr, isIpInRanges } from './ip-matcher';
import type { Identifier } from '../types';

export interface WhitelistConfig {
  /** Whitelisted IP addresses */
  ips?: string[];
  /** Whitelisted IP ranges (CIDR notation) */
  ipRanges?: string[];
  /** Whitelisted user IDs */
  userIds?: string[];
  /** Custom whitelist check function */
  customCheck?: (identifier: Identifier, context?: any) => boolean | Promise<boolean>;
}

export class Whitelist {
  private config: WhitelistConfig;

  constructor(config: WhitelistConfig = {}) {
    this.config = {
      ips: config.ips || [],
      ipRanges: config.ipRanges || [],
      userIds: config.userIds || [],
      customCheck: config.customCheck,
    };
  }

  /**
   * Check if identifier is whitelisted
   */
  async isWhitelisted(identifier: Identifier, context?: any): Promise<boolean> {
    // Check by type
    if (identifier.type === 'ip') {
      return this.isIpWhitelisted(identifier.value);
    }

    if (identifier.type === 'user') {
      return this.isUserWhitelisted(identifier.value);
    }

    // Custom check
    if (this.config.customCheck) {
      return await this.config.customCheck(identifier, context);
    }

    return false;
  }

  /**
   * Check if IP is whitelisted
   */
  private isIpWhitelisted(ip: string): boolean {
    // Check exact IP match
    if (this.config.ips && this.config.ips.includes(ip)) {
      return true;
    }

    // Check IP ranges
    if (this.config.ipRanges && this.config.ipRanges.length > 0) {
      return isIpInRanges(ip, this.config.ipRanges);
    }

    return false;
  }

  /**
   * Check if user ID is whitelisted
   */
  private isUserWhitelisted(userId: string): boolean {
    return !!(this.config.userIds && this.config.userIds.includes(userId));
  }

  /**
   * Add IP to whitelist
   */
  addIp(ip: string): void {
    if (!this.config.ips) {
      this.config.ips = [];
    }
    if (!this.config.ips.includes(ip)) {
      this.config.ips.push(ip);
    }
  }

  /**
   * Add IP range to whitelist
   */
  addIpRange(cidr: string): void {
    if (!this.config.ipRanges) {
      this.config.ipRanges = [];
    }
    if (!this.config.ipRanges.includes(cidr)) {
      this.config.ipRanges.push(cidr);
    }
  }

  /**
   * Add user ID to whitelist
   */
  addUserId(userId: string): void {
    if (!this.config.userIds) {
      this.config.userIds = [];
    }
    if (!this.config.userIds.includes(userId)) {
      this.config.userIds.push(userId);
    }
  }

  /**
   * Remove IP from whitelist
   */
  removeIp(ip: string): void {
    if (this.config.ips) {
      this.config.ips = this.config.ips.filter(i => i !== ip);
    }
  }

  /**
   * Remove IP range from whitelist
   */
  removeIpRange(cidr: string): void {
    if (this.config.ipRanges) {
      this.config.ipRanges = this.config.ipRanges.filter(r => r !== cidr);
    }
  }

  /**
   * Remove user ID from whitelist
   */
  removeUserId(userId: string): void {
    if (this.config.userIds) {
      this.config.userIds = this.config.userIds.filter(u => u !== userId);
    }
  }

  /**
   * Clear all whitelists
   */
  clear(): void {
    this.config.ips = [];
    this.config.ipRanges = [];
    this.config.userIds = [];
  }

  /**
   * Get whitelist stats
   */
  getStats() {
    return {
      ips: this.config.ips?.length || 0,
      ipRanges: this.config.ipRanges?.length || 0,
      userIds: this.config.userIds?.length || 0,
      total: (this.config.ips?.length || 0) + 
             (this.config.ipRanges?.length || 0) + 
             (this.config.userIds?.length || 0),
    };
  }
}

/**
 * Common whitelists for development/testing
 */
export const COMMON_WHITELISTS = {
  /** Localhost and private IPs */
  DEVELOPMENT: {
    ipRanges: [
      '127.0.0.0/8',    // Localhost
      '10.0.0.0/8',     // Private
      '172.16.0.0/12',  // Private
      '192.168.0.0/16', // Private
    ],
  },
  
  /** Cloudflare IPs (trusted proxy) */
  CLOUDFLARE: {
    ipRanges: [
      '173.245.48.0/20',
      '103.21.244.0/22',
      '103.22.200.0/22',
      '103.31.4.0/22',
      '141.101.64.0/18',
      '108.162.192.0/18',
      '190.93.240.0/20',
      '188.114.96.0/20',
      '197.234.240.0/22',
      '198.41.128.0/17',
      '162.158.0.0/15',
      '104.16.0.0/13',
      '104.24.0.0/14',
      '172.64.0.0/13',
      '131.0.72.0/22',
    ],
  },
};
