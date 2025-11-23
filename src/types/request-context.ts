/**
 * Extended request context for Cloudflare Workers
 */

/**
 * Cloudflare request context information
 */
export interface CloudflareContext {
  /** Client IP address */
  ip?: string;
  /** Country code (ISO 3166-1 alpha-2) */
  country?: string;
  /** City name */
  city?: string;
  /** Region/state code */
  region?: string;
  /** Postal code */
  postalCode?: string;
  /** Timezone */
  timezone?: string;
  /** ASN (Autonomous System Number) */
  asn?: number;
  /** ASN organization */
  asOrganization?: string;
  /** Latitude */
  latitude?: string;
  /** Longitude */
  longitude?: string;
  /** Is Tor exit node */
  isTorExitNode?: boolean;
  /** Is proxy */
  isProxy?: boolean;
  /** Cloudflare ray ID */
  rayId?: string;
  /** Colo (data center) */
  colo?: string;
}

/**
 * Request context with extracted information
 */
export interface RequestContext {
  /** Request object */
  request: Request;
  /** Cloudflare context */
  cf?: CloudflareContext;
  /** Extracted user ID (if authenticated) */
  userId?: string;
  /** Session ID */
  sessionId?: string;
  /** Custom metadata */
  metadata?: Record<string, any>;
  /** Request start time */
  startTime: number;
}

/**
 * Extract Cloudflare context from request
 */
export function extractCloudflareContext(request: Request): CloudflareContext {
  const cf = (request as any).cf;
  
  if (!cf) {
    return {};
  }

  return {
    ip: request.headers.get('CF-Connecting-IP') || undefined,
    country: cf.country,
    city: cf.city,
    region: cf.region,
    postalCode: cf.postalCode,
    timezone: cf.timezone,
    asn: cf.asn,
    asOrganization: cf.asOrganization,
    latitude: cf.latitude,
    longitude: cf.longitude,
    isTorExitNode: cf.isTorExitNode === '1',
    isProxy: cf.isProxy === '1',
    rayId: request.headers.get('CF-Ray') || undefined,
    colo: cf.colo,
  };
}

/**
 * Create request context from Request object
 */
export function createRequestContext(
  request: Request,
  metadata?: Record<string, any>
): RequestContext {
  return {
    request,
    cf: extractCloudflareContext(request),
    metadata,
    startTime: Date.now(),
  };
}
