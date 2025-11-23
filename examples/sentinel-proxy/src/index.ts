/**
 * Cloudflare Sentinel Proxy
 * 
 * Reverse proxy với full security protection cho website có sẵn
 * Deploy worker này trỏ về origin website để bảo vệ khỏi attacks
 */

import {
  Sentinel,
  // Request detectors
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  PathTraversalRequestDetector,
  BruteForceDetector,
  // Response detectors  
  SQLInjectionResponseDetector,
  XSSResponseDetector,
  PathTraversalResponseDetector,
  // Cleanup utilities
  cleanupD1Logs,
  cleanupKVStaleKeys,
  CLEANUP_CONFIGS,
  // Metrics
  SentinelMetricsCollector,
  // Notifications (NEW!)
  NotificationManager,
  EmailChannel,
  SlackChannel,
} from 'cloudflare-sentinel';

// Scheduled handler for notifications
import { handleScheduled as handleNotificationScheduled } from './scheduled';

export interface Env {
  // Cloudflare bindings
  RATE_LIMITER: any;
  DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  BEHAVIOR_KV: KVNamespace;
  ARCHIVE_BUCKET?: R2Bucket;
  
  // Config
  ORIGIN_URL: string;
  DEBUG?: 'true' | 'false';
  CLEANUP_MODE?: 'MINIMAL' | 'BALANCED' | 'CONSERVATIVE';
  ENABLE_ARCHIVE?: 'true' | 'false';
  ORIGIN_TIMEOUT?: string; // seconds, default 30
  MAX_REQUEST_SIZE?: string; // bytes, default 10MB
  ENABLE_STATIC_CACHE?: 'true' | 'false';
  
  // Notification Config (NEW!)
  EMAIL_ENABLED?: 'true' | 'false';
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  EMAIL_TO?: string;
  EMAIL_PROVIDER?: 'resend' | 'sendgrid';
  
  SLACK_ENABLED?: 'true' | 'false';
  SLACK_WEBHOOK_URL?: string;
  SLACK_CHANNEL?: string;
  SLACK_USERNAME?: string;
  SLACK_ICON_EMOJI?: string;
  
  NOTIFICATION_REALTIME_ENABLED?: 'true' | 'false';
  NOTIFICATION_REALTIME_SEVERITIES?: string;
  NOTIFICATION_REALTIME_MIN_CONFIDENCE?: string;
  NOTIFICATION_REALTIME_BLOCKED_ONLY?: 'true' | 'false';
  NOTIFICATION_RATE_LIMIT?: string;
  NOTIFICATION_RATE_PERIOD?: string;
  
  // Cron handler configs
  CRON_ATTACK_NOTIFIER?: string;
  ATTACK_NOTIFIER_PERIOD?: string;
  ATTACK_NOTIFIER_MIN_ATTACKS?: string;
  ATTACK_NOTIFIER_MIN_BLOCKED?: string;
  ATTACK_NOTIFIER_MIN_CRITICAL?: string;
  ATTACK_NOTIFIER_SEVERITIES?: string;
  
  CRON_REPORT_NOTIFIER?: string;
  REPORT_NOTIFIER_PERIOD?: string;
  
  CRON_SPIKE_DETECTOR?: string;
  SPIKE_DETECTOR_BASELINE_PERIOD?: string;
  SPIKE_DETECTOR_CHECK_PERIOD?: string;
  SPIKE_DETECTOR_THRESHOLD?: string;
  SPIKE_DETECTOR_MIN_ATTACKS?: string;
  
  CRON_METRICS_AGGREGATOR?: string;
  METRICS_AGGREGATOR_PERIOD?: string;
  METRICS_AGGREGATOR_MIN_REQUESTS?: string;
}


export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // Metrics endpoint (protect với Cloudflare Zero Trust)
    if (url.pathname === '/__sentinel/metrics') {
      try {
        // Create metrics collector - không cần Sentinel instance
        const metricsCollector = new SentinelMetricsCollector(
          env.DB,
          env.BEHAVIOR_KV,
          env.ANALYTICS
        );
        
        // Get metrics với options
        const period = url.searchParams.get('period') as '1h' | '24h' | '7d' | '30d' || '24h';
        const data = await metricsCollector.getMetrics({
          period,
          includeTopTargets: true,
          topLimit: 10,
        });
        
        return Response.json({
          status: 'ok',
          ...data,
        }, {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
          },
        });
      } catch (error: any) {
        return Response.json({
          status: 'error',
          error: error.message,
        }, { status: 500 });
      }
    }
    
    // Setup notification manager (if enabled)
    let notificationManager: NotificationManager | undefined;
    if (env.EMAIL_ENABLED === 'true' || env.SLACK_ENABLED === 'true') {
      notificationManager = new NotificationManager({
        rateLimit: {
          enabled: true,
          limit: parseInt(env.NOTIFICATION_RATE_LIMIT || '10'),
          period: parseInt(env.NOTIFICATION_RATE_PERIOD || '300'),
        },
        debug: env.DEBUG === 'true',
      });
      
      // Add email channel
      if (env.EMAIL_ENABLED === 'true' && env.RESEND_API_KEY) {
        notificationManager.addChannel(new EmailChannel({
          apiKey: env.RESEND_API_KEY,
          from: env.EMAIL_FROM || 'sentinel@yourdomain.com',
          to: (env.EMAIL_TO || '').split(',').filter(Boolean),
          provider: (env.EMAIL_PROVIDER as any) || 'resend',
        }));
      }
      
      // Add Slack channel
      if (env.SLACK_ENABLED === 'true' && env.SLACK_WEBHOOK_URL) {
        notificationManager.addChannel(new SlackChannel({
          webhookUrl: env.SLACK_WEBHOOK_URL,
          channel: env.SLACK_CHANNEL,
          username: env.SLACK_USERNAME || 'Sentinel',
          iconEmoji: env.SLACK_ICON_EMOJI || ':shield:',
        }));
      }
    }
    
    // Initialize Sentinel
    const sentinel = new Sentinel({
      // Bindings
      rateLimiter: env.RATE_LIMITER,
      db: env.DB,
      analytics: env.ANALYTICS,
      kv: env.BEHAVIOR_KV,
      
      // Notification config (NEW!)
      notification: notificationManager ? {
        enabled: true,
        manager: notificationManager,
        realtime: {
          enabled: env.NOTIFICATION_REALTIME_ENABLED === 'true',
          severities: env.NOTIFICATION_REALTIME_SEVERITIES?.split(',') as any,
          minConfidence: env.NOTIFICATION_REALTIME_MIN_CONFIDENCE 
            ? parseFloat(env.NOTIFICATION_REALTIME_MIN_CONFIDENCE)
            : 0.8,
          blockedOnly: env.NOTIFICATION_REALTIME_BLOCKED_ONLY === 'true',
        },
      } : undefined,
      
      // Built-in detectors (separated by request/response)
      detectors: [
        // Request detectors
        new SQLInjectionRequestDetector(),
        new XSSRequestDetector(),
        new PathTraversalRequestDetector(),
        new BruteForceDetector(),
        // Response detectors
        new SQLInjectionResponseDetector(),
        new XSSResponseDetector(),
        new PathTraversalResponseDetector(),
      ],
      
      // Attack limits
      attackLimits: {
        // Global limits
        sql_injection: {
          limit: 1,
          period: 604800,  // 7 days
          action: 'block',
        },
        xss: {
          limit: 5,
          period: 3600,  // 1 hour
          action: 'block',
        },
        path_traversal: {
          limit: 3,
          period: 3600,
          action: 'block',
        },
        
        // Endpoint-specific limits
        '/api/auth/*': {
          brute_force: {
            limit: 5,
            period: 300,  // 5 minutes
            action: 'block',
          },
        },
        '/admin/*': {
          '*': {
            limit: 10,
            period: 60,
            action: 'block',
          },
        },
      },
      
      // Features
      enableEarlyBlockCheck: true,
      enableBehaviorTracking: true,
      enableAnalytics: true,
      enableD1: true,
      debug: env.DEBUG === 'true',
    });
    
    // Check request size limit
    const contentLength = request.headers.get('content-length');
    const maxSize = parseInt(env.MAX_REQUEST_SIZE || '10485760'); // 10MB default
    if (contentLength && parseInt(contentLength) > maxSize) {
      return new Response('Payload Too Large', { 
        status: 413,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // Protect request và proxy to origin
    return sentinel.protect(request, async () => {
      // Forward to origin website
      const url = new URL(request.url);
      const originUrl = new URL(env.ORIGIN_URL);
      
      // Replace host với origin host
      url.hostname = originUrl.hostname;
      url.protocol = originUrl.protocol;
      if (originUrl.port) {
        url.port = originUrl.port;
      }
      
      // Clone request với new URL
      const modifiedRequest = new Request(url.toString(), {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: 'manual',
      });
      
      // Add security headers
      modifiedRequest.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
      modifiedRequest.headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
      modifiedRequest.headers.set('X-Forwarded-Host', request.headers.get('Host') || '');
      
      // Fetch from origin with timeout and error handling
      let response: Response;
      try {
        const timeout = parseInt(env.ORIGIN_TIMEOUT || '30') * 1000; // default 30s
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        response = await fetch(modifiedRequest, {
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);
        
      } catch (error: any) {
        // Handle fetch errors
        if (error.name === 'AbortError') {
          return new Response('Gateway Timeout - Origin server took too long to respond', {
            status: 504,
            headers: {
              'Content-Type': 'text/plain',
              'X-Protected-By': 'Cloudflare-Sentinel',
            },
          });
        }
        
        // Network error, DNS error, etc.
        console.error('Origin fetch error:', error.message);
        return new Response('Bad Gateway - Unable to reach origin server', {
          status: 502,
          headers: {
            'Content-Type': 'text/plain',
            'X-Protected-By': 'Cloudflare-Sentinel',
          },
        });
      }
      
      // Add security response headers
      const securedResponse = new Response(response.body, response);
      securedResponse.headers.set('X-Protected-By', 'Cloudflare-Sentinel');
      securedResponse.headers.set('X-Content-Type-Options', 'nosniff');
      securedResponse.headers.set('X-Frame-Options', 'SAMEORIGIN');
      
      // Optional: Cache static assets
      if (env.ENABLE_STATIC_CACHE === 'true' && request.method === 'GET') {
        const staticExtensions = /\.(jpg|jpeg|png|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot)$/i;
        if (staticExtensions.test(url.pathname)) {
          securedResponse.headers.set('Cache-Control', 'public, max-age=3600, immutable');
        }
      }
      
      return securedResponse;
    });
  },

  /**
   * Scheduled handler - handles both cleanup and notifications
   */
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const cron = event.cron;
    
    // Check if this is a notification cron
    const isNotificationCron = 
      cron === env.CRON_ATTACK_NOTIFIER ||
      cron === env.CRON_REPORT_NOTIFIER ||
      cron === env.CRON_SPIKE_DETECTOR ||
      cron === env.CRON_METRICS_AGGREGATOR;
    
    if (isNotificationCron) {
      // Handle notification crons
      console.log('📢 Handling notification cron...');
      await handleNotificationScheduled(event, env, ctx);
      return;
    }
    
    // Default: cleanup cron
    console.log('🧹 Starting cleanup...');
    
    const mode = env.CLEANUP_MODE || 'BALANCED';
    const config = {
      ...CLEANUP_CONFIGS[mode],
      archiveBeforeDelete: env.ENABLE_ARCHIVE === 'true' && !!env.ARCHIVE_BUCKET,
      r2Bucket: env.ARCHIVE_BUCKET,
    };

    // Cleanup D1 logs
    const d1Result = await cleanupD1Logs(env.DB, config);
    if (d1Result.success) {
      console.log(`✅ D1: Deleted ${d1Result.deleted}, Archived ${d1Result.archived || 0}`);
    } else {
      console.error('❌ D1 cleanup failed:', d1Result.errors);
    }

    // Cleanup KV stale keys
    const kvResult = await cleanupKVStaleKeys(env.BEHAVIOR_KV);
    if (kvResult.success) {
      console.log(`✅ KV: Deleted ${kvResult.deleted} stale keys`);
    }
  },
};
