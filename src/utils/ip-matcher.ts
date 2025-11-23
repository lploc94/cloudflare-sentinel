/**
 * IP matching utilities for CIDR ranges and IP blocking
 */

/**
 * Convert IP address to integer
 */
function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/**
 * Check if IP is in CIDR range
 * 
 * @example
 * isIpInCidr('192.168.1.100', '192.168.1.0/24') // true
 * isIpInCidr('10.0.0.1', '192.168.0.0/16') // false
 */
export function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const mask = -1 << (32 - parseInt(bits));
    
    const ipInt = ipToInt(ip);
    const rangeInt = ipToInt(range);
    
    return (ipInt & mask) === (rangeInt & mask);
  } catch {
    return false;
  }
}

/**
 * Check if IP is in any of the CIDR ranges
 * 
 * @example
 * isIpInRanges('192.168.1.5', ['192.168.0.0/16', '10.0.0.0/8'])
 */
export function isIpInRanges(ip: string, cidrs: string[]): boolean {
  return cidrs.some(cidr => isIpInCidr(ip, cidr));
}

/**
 * Check if IP is in blocklist
 */
export function isIpBlocked(ip: string, blocklist: string[]): boolean {
  return blocklist.includes(ip);
}

/**
 * Get IP subnet (first 3 octets)
 * 
 * @example
 * getIpSubnet('192.168.1.100') // '192.168.1'
 */
export function getIpSubnet(ip: string): string {
  const parts = ip.split('.');
  return parts.slice(0, 3).join('.');
}

/**
 * Get IP class C network
 * 
 * @example
 * getIpNetwork('192.168.1.100') // '192.168.1.0/24'
 */
export function getIpNetwork(ip: string): string {
  const subnet = getIpSubnet(ip);
  return `${subnet}.0/24`;
}

/**
 * Common IP range definitions
 */
export const IP_RANGES = {
  // Private networks
  PRIVATE: [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ],
  
  // Localhost
  LOCALHOST: ['127.0.0.0/8'],
  
  // Link-local
  LINK_LOCAL: ['169.254.0.0/16'],
  
  // Example/documentation
  DOCUMENTATION: [
    '192.0.2.0/24',
    '198.51.100.0/24',
    '203.0.113.0/24',
  ],
};

/**
 * Check if IP is private
 */
export function isPrivateIp(ip: string): boolean {
  return isIpInRanges(ip, IP_RANGES.PRIVATE);
}

/**
 * Check if IP is localhost
 */
export function isLocalhostIp(ip: string): boolean {
  return isIpInRanges(ip, IP_RANGES.LOCALHOST);
}

/**
 * Validate IPv4 address format
 */
export function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255 && part === num.toString();
  });
}

/**
 * Get subnet with specified prefix length
 * Used for rate limiting by subnet instead of individual IP
 * 
 * @param ip - IP address
 * @param prefixLength - CIDR prefix length (8, 16, 24, etc.)
 * @returns CIDR notation subnet
 * 
 * @example
 * getSubnet('192.168.1.100', 24) // '192.168.1.0/24'
 * getSubnet('10.50.30.20', 16) // '10.50.0.0/16'
 */
export function getSubnet(ip: string, prefixLength: number): string {
  if (!isValidIpv4(ip)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  
  if (prefixLength < 0 || prefixLength > 32) {
    throw new Error(`Invalid prefix length: ${prefixLength}. Must be 0-32`);
  }
  
  const ipInt = ipToInt(ip);
  const mask = -1 << (32 - prefixLength);
  const subnetInt = ipInt & mask;
  
  // Convert back to IP
  const octet1 = (subnetInt >>> 24) & 255;
  const octet2 = (subnetInt >>> 16) & 255;
  const octet3 = (subnetInt >>> 8) & 255;
  const octet4 = subnetInt & 255;
  
  return `${octet1}.${octet2}.${octet3}.${octet4}/${prefixLength}`;
}

/**
 * Parse IP address and extract information
 * 
 * @example
 * parseIp('192.168.1.100')
 * // {
 * //   ip: '192.168.1.100',
 * //   octets: [192, 168, 1, 100],
 * //   isPrivate: true,
 * //   isLocalhost: false,
 * //   subnet24: '192.168.1.0/24',
 * //   subnet16: '192.168.0.0/16',
 * // }
 */
export function parseIp(ip: string) {
  if (!isValidIpv4(ip)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  
  const octets = ip.split('.').map(Number);
  
  return {
    ip,
    octets,
    isPrivate: isPrivateIp(ip),
    isLocalhost: isLocalhostIp(ip),
    subnet24: getSubnet(ip, 24),
    subnet16: getSubnet(ip, 16),
    subnet8: getSubnet(ip, 8),
  };
}

/**
 * Anonymize IP address (for privacy compliance)
 * Zeros out last octet for IPv4
 * 
 * @example
 * anonymizeIp('192.168.1.100') // '192.168.1.0'
 */
export function anonymizeIp(ip: string): string {
  if (!isValidIpv4(ip)) {
    return ip; // Return as-is if invalid
  }
  
  const parts = ip.split('.');
  parts[3] = '0';
  return parts.join('.');
}

/**
 * Check if two IPs are in the same subnet
 * 
 * @example
 * isSameSubnet('192.168.1.100', '192.168.1.200', 24) // true
 * isSameSubnet('192.168.1.100', '192.168.2.100', 24) // false
 */
export function isSameSubnet(ip1: string, ip2: string, prefixLength: number): boolean {
  try {
    const subnet1 = getSubnet(ip1, prefixLength);
    const subnet2 = getSubnet(ip2, prefixLength);
    return subnet1 === subnet2;
  } catch {
    return false;
  }
}
