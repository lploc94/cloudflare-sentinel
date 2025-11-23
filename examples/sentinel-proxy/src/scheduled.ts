/**
 * Scheduled event handler (Cron Router)
 * Routes cron events to appropriate handlers
 */

import { handleAttackNotifier } from './cron/handlers/attack-notifier';
import { handleReportNotifier } from './cron/handlers/report-notifier';
import { handleSpikeDetector } from './cron/handlers/spike-detector';
import { handleMetricsAggregator } from './cron/handlers/metrics-aggregator';

/**
 * Handle scheduled events (cron triggers)
 * 
 * User configures cron schedules in wrangler.toml like:
 * 
 * ```
 * [[triggers.crons]]
 * schedule = "every 5 minutes"
 * handler = "attack-notifier"
 * ```
 * 
 * Or via environment variables:
 * ```
 * CRON_HANDLER_1 = "every 5 minutes|attack-notifier"
 * CRON_HANDLER_2 = "0 8 every day|report-notifier"
 * ```
 */
export async function handleScheduled(
  event: ScheduledEvent,
  env: any,
  ctx: ExecutionContext
): Promise<void> {
  const cron = event.cron;
  
  console.log(`[Scheduled] Cron triggered: ${cron}`);
  
  try {
    // Get handler name from environment variables
    // Format: CRON_{schedule_hash} = "handler_name|period"
    const handlerName = getCronHandler(cron, env);
    
    if (!handlerName) {
      console.error(`[Scheduled] No handler configured for cron: ${cron}`);
      return;
    }
    
    console.log(`[Scheduled] Executing handler: ${handlerName}`);
    
    // Route to appropriate handler
    switch (handlerName) {
      case 'attack-notifier':
        await handleAttackNotifier(
          env,
          env.ATTACK_NOTIFIER_PERIOD || '5m'
        );
        break;
        
      case 'report-notifier':
        await handleReportNotifier(
          env,
          env.REPORT_NOTIFIER_PERIOD || '24h'
        );
        break;
        
      case 'spike-detector':
        await handleSpikeDetector(env);
        break;
        
      case 'metrics-aggregator':
        await handleMetricsAggregator(
          env,
          env.METRICS_AGGREGATOR_PERIOD || '1h'
        );
        break;
        
      default:
        console.error(`[Scheduled] Unknown handler: ${handlerName}`);
    }
    
    console.log(`[Scheduled] Handler completed: ${handlerName}`);
  } catch (error: any) {
    console.error(`[Scheduled] Error:`, error.message);
    console.error(error.stack);
  }
}

/**
 * Get cron handler from environment variables
 * 
 * Looks for: CRON_{HANDLER_NAME} = "schedule|period"
 * Or fallback to schedule-based mapping
 */
function getCronHandler(cron: string, env: any): string | null {
  // Method 1: Direct mapping via environment variables
  // CRON_ATTACK_NOTIFIER = "*/5 * * * *"
  // CRON_REPORT_NOTIFIER = "0 8 * * *"
  // etc.
  
  const handlers = ['attack-notifier', 'report-notifier', 'spike-detector', 'metrics-aggregator'];
  
  for (const handler of handlers) {
    const envKey = `CRON_${handler.toUpperCase().replace(/-/g, '_')}`;
    const configuredCron = env[envKey];
    
    if (configuredCron === cron) {
      return handler;
    }
  }
  
  // Method 2: Fallback to default schedule mapping
  // User can customize by setting the env vars above
  const defaultMapping: Record<string, string> = {
    '*/5 * * * *': 'attack-notifier',     // Every 5 minutes
    '*/15 * * * *': 'spike-detector',     // Every 15 minutes
    '0 * * * *': 'metrics-aggregator',    // Every hour
    '0 8 * * *': 'report-notifier',       // Daily at 8am
  };
  
  return defaultMapping[cron] || null;
}
