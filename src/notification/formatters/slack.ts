/**
 * Slack-specific formatters
 * Format notifications as Slack Block Kit messages
 */

import type {
  AttackNotification,
  AttackSummary,
  AttackSpikeAlert,
  MetricsSummary,
} from '../../types/notification';

/**
 * Format attack notification for Slack
 */
export function formatSlackAttackNotification(attack: AttackNotification): any {
  const emoji = attack.severity === 'critical' ? ':rotating_light:' : attack.severity === 'high' ? ':warning:' : ':information_source:';
  const statusEmoji = attack.blocked ? ':white_check_mark:' : ':x:';
  const color = attack.severity === 'critical' ? '#dc2626' : attack.severity === 'high' ? '#ea580c' : '#3b82f6';

  return {
    attachments: [
      {
        color,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `${emoji} Attack Detected`,
              emoji: true,
            },
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Type:*\n${attack.attackType}`,
              },
              {
                type: 'mrkdwn',
                text: `*Severity:*\n${attack.severity.toUpperCase()}`,
              },
              {
                type: 'mrkdwn',
                text: `*Status:*\n${attack.blocked ? 'BLOCKED' : 'ALLOWED'} ${statusEmoji}`,
              },
              {
                type: 'mrkdwn',
                text: `*Confidence:*\n${(attack.confidence * 100).toFixed(0)}%`,
              },
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Attacker*\n• IP: \`${attack.attacker.ip}\`${attack.attacker.country ? ` :flag-${attack.attacker.country.toLowerCase()}:` : ''}\n• UA: ${attack.attacker.userAgent || 'Unknown'}`,
            },
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Target*\n• Endpoint: \`${attack.target.endpoint}\`\n• Method: \`${attack.target.method}\``,
            },
          },
          ...(attack.evidence ? [{
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Evidence*\n• Field: ${attack.evidence.field}\n• Value: \`${attack.evidence.value}\`${attack.evidence.pattern ? `\n• Pattern: ${attack.evidence.pattern}` : ''}`,
            },
          }] : []),
          {
            type: 'context',
            elements: [
              {
                type: 'mrkdwn',
                text: `_${attack.timestamp}_`,
              },
            ],
          },
        ],
      },
    ],
  };
}

/**
 * Format attack summary for Slack
 */
export function formatSlackAttackSummary(summary: AttackSummary): any {
  const blockRate = ((summary.totals.blocked / summary.totals.attacks) * 100).toFixed(1);

  return {
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: '📊 Attack Summary',
          emoji: true,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Period:* ${summary.period.duration}\n*From:* ${summary.period.start}\n*To:* ${summary.period.end}`,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Total Attacks*\n${summary.totals.attacks}`,
          },
          {
            type: 'mrkdwn',
            text: `*Blocked*\n${summary.totals.blocked} (${blockRate}%)`,
          },
          {
            type: 'mrkdwn',
            text: `*Unique IPs*\n${summary.totals.uniqueIPs}`,
          },
          {
            type: 'mrkdwn',
            text: `*Affected Endpoints*\n${summary.totals.affectedEndpoints}`,
          },
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Attacks by Type*\n${Object.entries(summary.byType).slice(0, 5).map(([type, data]) => 
            `• ${type}: ${data.count} (${((data.count / summary.totals.attacks) * 100).toFixed(1)}%)`
          ).join('\n')}`,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Top Attackers*\n${summary.topAttackers.slice(0, 3).map((a, i) => 
              `${i + 1}. \`${a.ip}\` - ${a.attacks} attacks`
            ).join('\n')}`,
          },
          {
            type: 'mrkdwn',
            text: `*Top Targets*\n${summary.topTargets.slice(0, 3).map((t, i) => 
              `${i + 1}. \`${t.endpoint}\` - ${t.attacks} attacks`
            ).join('\n')}`,
          },
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Severity:* Critical: ${summary.bySeverity.critical} | High: ${summary.bySeverity.high} | Medium: ${summary.bySeverity.medium} | Low: ${summary.bySeverity.low}`,
        },
      },
    ],
  };
}

/**
 * Format attack spike for Slack
 */
export function formatSlackAttackSpike(spike: AttackSpikeAlert): any {
  return {
    attachments: [
      {
        color: '#dc2626',
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: ':rotating_light: Attack Spike Detected',
              emoji: true,
            },
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Current*\n${spike.current} attacks`,
              },
              {
                type: 'mrkdwn',
                text: `*Baseline*\n${spike.baseline} attacks`,
              },
              {
                type: 'mrkdwn',
                text: `*Increase*\n${spike.increase}`,
              },
              {
                type: 'mrkdwn',
                text: `*Threshold*\n${spike.threshold}x baseline`,
              },
            ],
          },
          {
            type: 'context',
            elements: [
              {
                type: 'mrkdwn',
                text: `Period: ${spike.period} | _${spike.timestamp}_`,
              },
            ],
          },
        ],
      },
    ],
  };
}

/**
 * Format metrics summary for Slack
 */
export function formatSlackMetricsSummary(metrics: MetricsSummary): any {
  return {
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: '📊 Metrics Summary',
          emoji: true,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Period:* ${metrics.period}`,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Total Requests*\n${metrics.requests.total}`,
          },
          {
            type: 'mrkdwn',
            text: `*Blocked*\n${metrics.requests.blocked}`,
          },
          {
            type: 'mrkdwn',
            text: `*Allowed*\n${metrics.requests.allowed}`,
          },
          {
            type: 'mrkdwn',
            text: `*Block Rate*\n${metrics.requests.blockRate}`,
          },
        ],
      },
      ...(metrics.performance ? [{
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Performance*\nAvg: ${metrics.performance.avgResponseTime} | Min: ${metrics.performance.minResponseTime} | Max: ${metrics.performance.maxResponseTime}`,
        },
      }] : []),
      ...(metrics.cache ? [{
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Cache*\nHits: ${metrics.cache.hits} | Misses: ${metrics.cache.misses} | Hit Rate: ${metrics.cache.hitRate}`,
        },
      }] : []),
    ],
  };
}
