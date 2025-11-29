/**
 * Data extraction utilities
 */

/**
 * Extract client IP from request headers
 * 
 * Checks in order:
 * 1. cf-connecting-ip (Cloudflare)
 * 2. x-forwarded-for (first IP)
 * 3. x-real-ip
 * 
 * @example
 * ```typescript
 * const ip = extractIP(request);
 * if (ip) {
 *   console.log(`Request from: ${ip}`);
 * }
 * ```
 */
export function extractIP(request: Request): string | null {
  // Cloudflare header (most reliable)
  const cfIP = request.headers.get('cf-connecting-ip');
  if (cfIP) return cfIP;

  // X-Forwarded-For (may contain multiple IPs, first is client)
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    const firstIP = xff.split(',')[0]?.trim();
    if (firstIP) return firstIP;
  }

  // X-Real-IP fallback
  const realIP = request.headers.get('x-real-ip');
  if (realIP) return realIP;

  return null;
}

/**
 * Extract IP from HandlerContext
 * 
 * Tries to get IP from:
 * 1. Detection results evidence (field: 'ip')
 * 2. Original request headers
 * 
 * @example
 * ```typescript
 * class MyHandler implements IActionHandler {
 *   async execute(action: Action, ctx: HandlerContext) {
 *     const ip = extractIPFromContext(ctx);
 *     // ...
 *   }
 * }
 * ```
 */
export function extractIPFromContext(ctx: {
  results?: Array<{ evidence?: { field?: string; value?: any } }>;
  request?: Request;
}): string | null {
  // Try to get from detection results
  if (ctx.results) {
    for (const result of ctx.results) {
      if (result.evidence?.field === 'ip' && result.evidence?.value) {
        return String(result.evidence.value);
      }
    }
  }

  // Fallback to request headers
  if (ctx.request) {
    return extractIP(ctx.request);
  }

  return null;
}
