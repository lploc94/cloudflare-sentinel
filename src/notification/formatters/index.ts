/**
 * Notification formatters
 * Format notification data for different output formats (text, html, slack blocks)
 */

import type {
  AttackNotification,
  AttackSummary,
  AttackSpikeAlert,
  MetricsSummary,
  NotificationPayload,
} from '../../types/notification';

/**
 * Format attack notification for text/email
 */
export function formatAttackNotification(attack: AttackNotification): {
  subject: string;
  text: string;
  html: string;
} {
  const emoji = attack.severity === 'critical' ? '🚨' : attack.severity === 'high' ? '⚠️' : 'ℹ️';
  const statusEmoji = attack.blocked ? '✅' : '❌';
  const statusText = attack.blocked ? 'BLOCKED' : 'ALLOWED';

  const subject = `${emoji} ${attack.severity.toUpperCase()} Attack - ${attack.attackType}`;

  const text = `
${emoji} ATTACK DETECTED

Attack Details:
- Type: ${attack.attackType}
- Severity: ${attack.severity.toUpperCase()}
- Status: ${statusText} ${statusEmoji}
- Confidence: ${(attack.confidence * 100).toFixed(0)}%

Attacker:
- IP: ${attack.attacker.ip}${attack.attacker.country ? ` (${attack.attacker.country})` : ''}
- User-Agent: ${attack.attacker.userAgent || 'Unknown'}

Target:
- Endpoint: ${attack.target.endpoint}
- Method: ${attack.target.method}

${attack.evidence ? `Evidence:
- Field: ${attack.evidence.field}
- Value: ${attack.evidence.value}
- Pattern: ${attack.evidence.pattern || 'N/A'}
` : ''}
Timestamp: ${attack.timestamp}
`.trim();

  const html = `
<div style="font-family: Arial, sans-serif; max-width: 600px;">
  <h2 style="color: ${attack.severity === 'critical' ? '#dc2626' : attack.severity === 'high' ? '#ea580c' : '#3b82f6'};">
    ${emoji} Attack Detected
  </h2>
  
  <div style="background: #f3f4f6; padding: 16px; border-radius: 8px; margin: 16px 0;">
    <h3 style="margin-top: 0;">Attack Details</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Type:</strong></td><td>${attack.attackType}</td></tr>
      <tr><td><strong>Severity:</strong></td><td><span style="color: ${attack.severity === 'critical' ? '#dc2626' : '#ea580c'};">${attack.severity.toUpperCase()}</span></td></tr>
      <tr><td><strong>Status:</strong></td><td>${statusText} ${statusEmoji}</td></tr>
      <tr><td><strong>Confidence:</strong></td><td>${(attack.confidence * 100).toFixed(0)}%</td></tr>
    </table>
  </div>

  <div style="background: #fef3c7; padding: 16px; border-radius: 8px; margin: 16px 0;">
    <h3 style="margin-top: 0;">Attacker</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>IP:</strong></td><td>${attack.attacker.ip}${attack.attacker.country ? ` (${attack.attacker.country})` : ''}</td></tr>
      <tr><td><strong>User-Agent:</strong></td><td>${attack.attacker.userAgent || 'Unknown'}</td></tr>
    </table>
  </div>

  <div style="background: #e0e7ff; padding: 16px; border-radius: 8px; margin: 16px 0;">
    <h3 style="margin-top: 0;">Target</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Endpoint:</strong></td><td><code>${attack.target.endpoint}</code></td></tr>
      <tr><td><strong>Method:</strong></td><td><code>${attack.target.method}</code></td></tr>
    </table>
  </div>

  ${attack.evidence ? `
  <div style="background: #fee2e2; padding: 16px; border-radius: 8px; margin: 16px 0;">
    <h3 style="margin-top: 0;">Evidence</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Field:</strong></td><td>${attack.evidence.field}</td></tr>
      <tr><td><strong>Value:</strong></td><td><code style="word-break: break-all;">${attack.evidence.value}</code></td></tr>
      ${attack.evidence.pattern ? `<tr><td><strong>Pattern:</strong></td><td>${attack.evidence.pattern}</td></tr>` : ''}
    </table>
  </div>
  ` : ''}

  <p style="color: #6b7280; font-size: 14px; margin-top: 24px;">
    Timestamp: ${attack.timestamp}
  </p>
</div>
`.trim();

  return { subject, text, html };
}

/**
 * Format attack summary for text/email
 */
export function formatAttackSummary(summary: AttackSummary, detailed: boolean = false): {
  subject: string;
  text: string;
  html: string;
} {
  const subject = `📊 Attack Summary - ${summary.totals.attacks} attacks (${summary.period.duration})`;

  const text = `
📊 ATTACK SUMMARY

Period: ${summary.period.duration}
From: ${summary.period.start}
To: ${summary.period.end}

Summary:
- Total Attacks: ${summary.totals.attacks}
- Blocked: ${summary.totals.blocked} (${((summary.totals.blocked / summary.totals.attacks) * 100).toFixed(1)}%)
- Allowed: ${summary.totals.allowed} (${((summary.totals.allowed / summary.totals.attacks) * 100).toFixed(1)}%)
- Unique IPs: ${summary.totals.uniqueIPs}
- Affected Endpoints: ${summary.totals.affectedEndpoints}

Attacks by Type:
${Object.entries(summary.byType).map(([type, data]) => 
  `- ${type}: ${data.count} (${((data.count / summary.totals.attacks) * 100).toFixed(1)}%)`
).join('\n')}

Top Attackers:
${summary.topAttackers.slice(0, 5).map((attacker, i) => 
  `${i + 1}. ${attacker.ip}${attacker.country ? ` (${attacker.country})` : ''} - ${attacker.attacks} attacks`
).join('\n')}

Top Targets:
${summary.topTargets.slice(0, 5).map((target, i) => 
  `${i + 1}. ${target.endpoint} - ${target.attacks} attacks`
).join('\n')}

Severity Breakdown:
- Critical: ${summary.bySeverity.critical}
- High: ${summary.bySeverity.high}
- Medium: ${summary.bySeverity.medium}
- Low: ${summary.bySeverity.low}
`.trim();

  const html = `
<div style="font-family: Arial, sans-serif; max-width: 800px;">
  <h2>📊 Attack Summary</h2>
  
  <p><strong>Period:</strong> ${summary.period.duration}<br>
  <strong>From:</strong> ${summary.period.start}<br>
  <strong>To:</strong> ${summary.period.end}</p>

  <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h3>Summary</h3>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
      <div style="background: white; padding: 16px; border-radius: 8px;">
        <div style="font-size: 32px; font-weight: bold; color: #3b82f6;">${summary.totals.attacks}</div>
        <div style="color: #6b7280;">Total Attacks</div>
      </div>
      <div style="background: white; padding: 16px; border-radius: 8px;">
        <div style="font-size: 32px; font-weight: bold; color: #10b981;">${summary.totals.blocked}</div>
        <div style="color: #6b7280;">Blocked (${((summary.totals.blocked / summary.totals.attacks) * 100).toFixed(1)}%)</div>
      </div>
      <div style="background: white; padding: 16px; border-radius: 8px;">
        <div style="font-size: 32px; font-weight: bold; color: #f59e0b;">${summary.totals.uniqueIPs}</div>
        <div style="color: #6b7280;">Unique IPs</div>
      </div>
    </div>
  </div>

  <div style="background: #fef3c7; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h3>Attacks by Type</h3>
    <table style="width: 100%; border-collapse: collapse;">
      ${Object.entries(summary.byType).map(([type, data]) => `
        <tr>
          <td style="padding: 8px;"><strong>${type}</strong></td>
          <td style="padding: 8px;">${data.count}</td>
          <td style="padding: 8px;">${((data.count / summary.totals.attacks) * 100).toFixed(1)}%</td>
          <td style="padding: 8px;"><span style="background: ${data.severity === 'critical' ? '#dc2626' : data.severity === 'high' ? '#ea580c' : '#3b82f6'}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">${data.severity}</span></td>
        </tr>
      `).join('')}
    </table>
  </div>

  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
    <div style="background: #e0e7ff; padding: 20px; border-radius: 8px;">
      <h3>Top Attackers</h3>
      <ol style="margin: 0; padding-left: 20px;">
        ${summary.topAttackers.slice(0, 5).map(attacker => `
          <li style="margin: 8px 0;">
            <strong>${attacker.ip}</strong>${attacker.country ? ` (${attacker.country})` : ''}<br>
            <span style="color: #6b7280; font-size: 14px;">${attacker.attacks} attacks • ${attacker.blocked} blocked</span>
          </li>
        `).join('')}
      </ol>
    </div>

    <div style="background: #e0e7ff; padding: 20px; border-radius: 8px;">
      <h3>Top Targets</h3>
      <ol style="margin: 0; padding-left: 20px;">
        ${summary.topTargets.slice(0, 5).map(target => `
          <li style="margin: 8px 0;">
            <code>${target.endpoint}</code><br>
            <span style="color: #6b7280; font-size: 14px;">${target.attacks} attacks • ${target.blocked} blocked</span>
          </li>
        `).join('')}
      </ol>
    </div>
  </div>

  <div style="background: #fee2e2; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h3>Severity Breakdown</h3>
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px;">
      <div><strong>Critical:</strong> ${summary.bySeverity.critical}</div>
      <div><strong>High:</strong> ${summary.bySeverity.high}</div>
      <div><strong>Medium:</strong> ${summary.bySeverity.medium}</div>
      <div><strong>Low:</strong> ${summary.bySeverity.low}</div>
    </div>
  </div>
</div>
`.trim();

  return { subject, text, html };
}

/**
 * Format attack spike alert
 */
export function formatAttackSpikeAlert(spike: AttackSpikeAlert): {
  subject: string;
  text: string;
  html: string;
} {
  const subject = `🚨 Attack Spike Detected - ${spike.increase} increase`;

  const text = `
🚨 ATTACK SPIKE DETECTED

Current: ${spike.current} attacks
Baseline: ${spike.baseline} attacks
Increase: ${spike.increase}
Threshold: ${spike.threshold}x baseline
Period: ${spike.period}

Timestamp: ${spike.timestamp}
`.trim();

  const html = `
<div style="font-family: Arial, sans-serif; max-width: 600px;">
  <h2 style="color: #dc2626;">🚨 Attack Spike Detected</h2>
  
  <div style="background: #fee2e2; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Current:</strong></td><td style="font-size: 24px; color: #dc2626;">${spike.current} attacks</td></tr>
      <tr><td><strong>Baseline:</strong></td><td>${spike.baseline} attacks</td></tr>
      <tr><td><strong>Increase:</strong></td><td style="font-size: 20px; color: #dc2626;">${spike.increase}</td></tr>
      <tr><td><strong>Threshold:</strong></td><td>${spike.threshold}x baseline</td></tr>
      <tr><td><strong>Period:</strong></td><td>${spike.period}</td></tr>
    </table>
  </div>

  <p style="color: #6b7280; font-size: 14px;">
    Timestamp: ${spike.timestamp}
  </p>
</div>
`.trim();

  return { subject, text, html };
}

/**
 * Format metrics summary
 */
export function formatMetricsSummary(metrics: MetricsSummary): {
  subject: string;
  text: string;
  html: string;
} {
  const subject = `📊 Metrics Summary - ${metrics.period}`;

  const text = `
📊 METRICS SUMMARY

Period: ${metrics.period}

Requests:
- Total: ${metrics.requests.total}
- Blocked: ${metrics.requests.blocked}
- Allowed: ${metrics.requests.allowed}
- Block Rate: ${metrics.requests.blockRate}

${metrics.performance ? `Performance:
- Avg Response Time: ${metrics.performance.avgResponseTime}
- Min: ${metrics.performance.minResponseTime}
- Max: ${metrics.performance.maxResponseTime}
` : ''}
${metrics.cache ? `Cache:
- Hits: ${metrics.cache.hits}
- Misses: ${metrics.cache.misses}
- Hit Rate: ${metrics.cache.hitRate}
` : ''}
`.trim();

  const html = `
<div style="font-family: Arial, sans-serif; max-width: 600px;">
  <h2>📊 Metrics Summary</h2>
  <p><strong>Period:</strong> ${metrics.period}</p>

  <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h3>Requests</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Total:</strong></td><td>${metrics.requests.total}</td></tr>
      <tr><td><strong>Blocked:</strong></td><td style="color: #dc2626;">${metrics.requests.blocked}</td></tr>
      <tr><td><strong>Allowed:</strong></td><td style="color: #10b981;">${metrics.requests.allowed}</td></tr>
      <tr><td><strong>Block Rate:</strong></td><td>${metrics.requests.blockRate}</td></tr>
    </table>
  </div>

  ${metrics.performance ? `
  <div style="background: #e0e7ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h3>Performance</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Avg:</strong></td><td>${metrics.performance.avgResponseTime}</td></tr>
      <tr><td><strong>Min:</strong></td><td>${metrics.performance.minResponseTime}</td></tr>
      <tr><td><strong>Max:</strong></td><td>${metrics.performance.maxResponseTime}</td></tr>
    </table>
  </div>
  ` : ''}

  ${metrics.cache ? `
  <div style="background: #fef3c7; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h3>Cache</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td><strong>Hits:</strong></td><td>${metrics.cache.hits}</td></tr>
      <tr><td><strong>Misses:</strong></td><td>${metrics.cache.misses}</td></tr>
      <tr><td><strong>Hit Rate:</strong></td><td>${metrics.cache.hitRate}</td></tr>
    </table>
  </div>
  ` : ''}
</div>
`.trim();

  return { subject, text, html };
}
