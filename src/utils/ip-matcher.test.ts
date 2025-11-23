/**
 * Unit tests for IP utilities
 */

import { describe, it, expect } from 'vitest';
import {
  isValidIpv4,
  isIpInCidr,
  isIpInRanges,
  getSubnet,
  parseIp,
  anonymizeIp,
  isSameSubnet,
  isPrivateIp,
  isLocalhostIp,
} from './ip-matcher';

describe('IP Matcher Utilities', () => {
  describe('isValidIpv4', () => {
    it('should validate correct IPv4 addresses', () => {
      expect(isValidIpv4('192.168.1.1')).toBe(true);
      expect(isValidIpv4('10.0.0.1')).toBe(true);
      expect(isValidIpv4('255.255.255.255')).toBe(true);
      expect(isValidIpv4('0.0.0.0')).toBe(true);
    });

    it('should reject invalid IPv4 addresses', () => {
      expect(isValidIpv4('256.1.1.1')).toBe(false);
      expect(isValidIpv4('192.168.1')).toBe(false);
      expect(isValidIpv4('192.168.1.1.1')).toBe(false);
      expect(isValidIpv4('abc.def.ghi.jkl')).toBe(false);
      expect(isValidIpv4('')).toBe(false);
    });
  });

  describe('isIpInCidr', () => {
    it('should match IP in CIDR range', () => {
      expect(isIpInCidr('192.168.1.100', '192.168.1.0/24')).toBe(true);
      expect(isIpInCidr('10.50.30.20', '10.50.0.0/16')).toBe(true);
      expect(isIpInCidr('172.16.0.1', '172.16.0.0/12')).toBe(true);
    });

    it('should not match IP outside CIDR range', () => {
      expect(isIpInCidr('192.168.2.1', '192.168.1.0/24')).toBe(false);
      expect(isIpInCidr('10.51.0.1', '10.50.0.0/16')).toBe(false);
    });

    it('should handle /32 (single IP)', () => {
      expect(isIpInCidr('192.168.1.1', '192.168.1.1/32')).toBe(true);
      expect(isIpInCidr('192.168.1.2', '192.168.1.1/32')).toBe(false);
    });
  });

  describe('isIpInRanges', () => {
    it('should match IP in any of the ranges', () => {
      const ranges = ['192.168.0.0/16', '10.0.0.0/8'];
      expect(isIpInRanges('192.168.1.1', ranges)).toBe(true);
      expect(isIpInRanges('10.50.30.20', ranges)).toBe(true);
    });

    it('should not match IP outside all ranges', () => {
      const ranges = ['192.168.0.0/16', '10.0.0.0/8'];
      expect(isIpInRanges('172.16.0.1', ranges)).toBe(false);
    });
  });

  describe('getSubnet', () => {
    it('should calculate /24 subnet correctly', () => {
      expect(getSubnet('192.168.1.100', 24)).toBe('192.168.1.0/24');
      expect(getSubnet('10.50.30.200', 24)).toBe('10.50.30.0/24');
    });

    it('should calculate /16 subnet correctly', () => {
      expect(getSubnet('192.168.1.100', 16)).toBe('192.168.0.0/16');
      expect(getSubnet('10.50.30.200', 16)).toBe('10.50.0.0/16');
    });

    it('should calculate /8 subnet correctly', () => {
      expect(getSubnet('192.168.1.100', 8)).toBe('192.0.0.0/8');
      expect(getSubnet('10.50.30.200', 8)).toBe('10.0.0.0/8');
    });

    it('should handle edge cases', () => {
      expect(getSubnet('255.255.255.255', 32)).toBe('255.255.255.255/32');
      expect(getSubnet('0.0.0.0', 0)).toBe('0.0.0.0/0');
    });

    it('should throw on invalid IP', () => {
      expect(() => getSubnet('invalid', 24)).toThrow('Invalid IPv4 address');
    });

    it('should throw on invalid prefix length', () => {
      expect(() => getSubnet('192.168.1.1', -1)).toThrow('Invalid prefix length');
      expect(() => getSubnet('192.168.1.1', 33)).toThrow('Invalid prefix length');
    });
  });

  describe('parseIp', () => {
    it('should parse IP and extract information', () => {
      const result = parseIp('192.168.1.100');
      
      expect(result.ip).toBe('192.168.1.100');
      expect(result.octets).toEqual([192, 168, 1, 100]);
      expect(result.isPrivate).toBe(true);
      expect(result.isLocalhost).toBe(false);
      expect(result.subnet24).toBe('192.168.1.0/24');
      expect(result.subnet16).toBe('192.168.0.0/16');
    });

    it('should detect localhost', () => {
      const result = parseIp('127.0.0.1');
      expect(result.isLocalhost).toBe(true);
      expect(result.isPrivate).toBe(false);
    });

    it('should throw on invalid IP', () => {
      expect(() => parseIp('invalid')).toThrow('Invalid IPv4 address');
    });
  });

  describe('anonymizeIp', () => {
    it('should zero out last octet', () => {
      expect(anonymizeIp('192.168.1.100')).toBe('192.168.1.0');
      expect(anonymizeIp('10.50.30.200')).toBe('10.50.30.0');
    });

    it('should return invalid IP as-is', () => {
      expect(anonymizeIp('invalid')).toBe('invalid');
    });
  });

  describe('isSameSubnet', () => {
    it('should return true for IPs in same /24 subnet', () => {
      expect(isSameSubnet('192.168.1.100', '192.168.1.200', 24)).toBe(true);
      expect(isSameSubnet('10.50.30.1', '10.50.30.255', 24)).toBe(true);
    });

    it('should return false for IPs in different /24 subnets', () => {
      expect(isSameSubnet('192.168.1.100', '192.168.2.100', 24)).toBe(false);
      expect(isSameSubnet('10.50.30.1', '10.50.31.1', 24)).toBe(false);
    });

    it('should work with /16 subnets', () => {
      expect(isSameSubnet('192.168.1.1', '192.168.255.1', 16)).toBe(true);
      expect(isSameSubnet('192.168.1.1', '192.169.1.1', 16)).toBe(false);
    });

    it('should handle invalid IPs gracefully', () => {
      expect(isSameSubnet('invalid', '192.168.1.1', 24)).toBe(false);
      expect(isSameSubnet('192.168.1.1', 'invalid', 24)).toBe(false);
    });
  });

  describe('isPrivateIp', () => {
    it('should detect private IP ranges', () => {
      expect(isPrivateIp('192.168.1.1')).toBe(true);
      expect(isPrivateIp('10.0.0.1')).toBe(true);
      expect(isPrivateIp('172.16.0.1')).toBe(true);
      expect(isPrivateIp('172.31.255.255')).toBe(true);
    });

    it('should not detect public IPs as private', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false);
      expect(isPrivateIp('1.1.1.1')).toBe(false);
      expect(isPrivateIp('172.32.0.1')).toBe(false);
    });
  });

  describe('isLocalhostIp', () => {
    it('should detect localhost IPs', () => {
      expect(isLocalhostIp('127.0.0.1')).toBe(true);
      expect(isLocalhostIp('127.0.0.2')).toBe(true);
      expect(isLocalhostIp('127.255.255.255')).toBe(true);
    });

    it('should not detect non-localhost IPs', () => {
      expect(isLocalhostIp('192.168.1.1')).toBe(false);
      expect(isLocalhostIp('128.0.0.1')).toBe(false);
    });
  });
});
