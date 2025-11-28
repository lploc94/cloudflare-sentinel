/**
 * Cloudflare Sentinel Proxy
 * 
 * Security reverse proxy for legacy websites.
 * Protects any website without modifying backend code.
 * 
 * Usage:
 * 1. Edit sentinel.config.ts to customize protection
 * 2. Deploy: wrangler deploy
 * 3. Point your domain to this worker
 * 4. Done! Your site is now protected.
 */

import { matchRoute, buildPipeline, buildResponsePipeline, type Env } from './lib';
import { createConfig } from './sentinel.config';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // ════════════════════════════════════════════════════════════════════════
    // HEALTH CHECK
    // ════════════════════════════════════════════════════════════════════════
    if (url.pathname === '/__sentinel/health') {
      return Response.json({ 
        status: 'ok', 
        timestamp: Date.now(),
        version: '2.0.0',
      });
    }
    
    // ════════════════════════════════════════════════════════════════════════
    // CREATE CONFIG
    // ════════════════════════════════════════════════════════════════════════
    const config = createConfig(env);
    
    // ════════════════════════════════════════════════════════════════════════
    // ROUTE MATCHING
    // ════════════════════════════════════════════════════════════════════════
    const matched = matchRoute(url.pathname, config.routes);
    
    // Skip security if route config says so
    if ((matched?.config as any)?.skip) {
      return proxyToOrigin(request, env);
    }
    
    // ════════════════════════════════════════════════════════════════════════
    // BUILD PIPELINE (global + route extend)
    // ════════════════════════════════════════════════════════════════════════
    const pipeline = buildPipeline(config, matched?.config, env);
    const pctx = { env, ctx };
    
    // ════════════════════════════════════════════════════════════════════════
    // REQUEST DETECTION
    // ════════════════════════════════════════════════════════════════════════
    const decision = await pipeline.process(request, pctx);
    
    if (decision?.has('block')) {
      const blockData = decision.get('block');
      return new Response(blockData?.reason || 'Request blocked by Sentinel', {
        status: blockData?.statusCode || 403,
        headers: {
          'Content-Type': 'text/plain',
          'X-Protected-By': 'Cloudflare-Sentinel',
          'X-Block-Reason': blockData?.reason || 'Security violation',
        },
      });
    }
    
    // ════════════════════════════════════════════════════════════════════════
    // PROXY TO ORIGIN
    // ════════════════════════════════════════════════════════════════════════
    const response = await proxyToOrigin(request, env);
    
    // ════════════════════════════════════════════════════════════════════════
    // RESPONSE DETECTION (if enabled in config)
    // ════════════════════════════════════════════════════════════════════════
    const responsePipeline = buildResponsePipeline(config, env);
    if (responsePipeline) {
      const respDecision = await responsePipeline.processResponse(
        request,
        response,
        pctx
      );
      
      if (respDecision?.has('block')) {
        return new Response('Response blocked - potential data leak detected', {
          status: 500,
          headers: {
            'Content-Type': 'text/plain',
            'X-Protected-By': 'Cloudflare-Sentinel',
          },
        });
      }
    }
    
    // ════════════════════════════════════════════════════════════════════════
    // ADD SECURITY HEADERS & RETURN
    // ════════════════════════════════════════════════════════════════════════
    const securedResponse = new Response(response.body, response);
    securedResponse.headers.set('X-Protected-By', 'Cloudflare-Sentinel');
    securedResponse.headers.set('X-Content-Type-Options', 'nosniff');
    securedResponse.headers.set('X-Frame-Options', 'SAMEORIGIN');
    securedResponse.headers.set('X-XSS-Protection', '1; mode=block');
    
    return securedResponse;
  },
};

/**
 * Proxy request to origin server
 */
async function proxyToOrigin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const originUrl = new URL(env.ORIGIN_URL);
  
  // Replace host with origin
  url.hostname = originUrl.hostname;
  url.protocol = originUrl.protocol;
  if (originUrl.port) {
    url.port = originUrl.port;
  }
  
  // Create proxied request
  const proxyRequest = new Request(url.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body,
    redirect: 'manual',
  });
  
  // Add forwarding headers
  proxyRequest.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
  proxyRequest.headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
  proxyRequest.headers.set('X-Forwarded-Host', request.headers.get('Host') || '');
  proxyRequest.headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || '');
  
  // Fetch with timeout
  try {
    const timeout = parseInt(env.ORIGIN_TIMEOUT || '30') * 1000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    const response = await fetch(proxyRequest, {
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    return response;
    
  } catch (error: any) {
    if (error.name === 'AbortError') {
      return new Response('Gateway Timeout', {
        status: 504,
        headers: { 'Content-Type': 'text/plain' },
      });
    }
    
    console.error('[Sentinel] Origin error:', error.message);
    return new Response('Bad Gateway', {
      status: 502,
      headers: { 'Content-Type': 'text/plain' },
    });
  }
}

// Re-export Env type for external use
export type { Env };
