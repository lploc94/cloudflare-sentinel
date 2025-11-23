# Notification System

Internal guide for contributors working on notifications.

## Architecture

```
NotificationManager (orchestrator)
    ↓
Channels (pluggable)
    ├─ EmailChannel
    ├─ SlackChannel
    └─ [Your channel]
```

## File Structure

```
notification/
├── index.ts                 # NotificationManager
├── base.ts                  # BaseNotificationChannel
├── rate-limiter.ts          # Rate limiting
├── channels/
│   ├── email.ts             # EmailChannel
│   ├── slack.ts             # SlackChannel
│   └── index.ts
└── formatters/
    ├── index.ts             # Email formatters
    └── slack.ts             # Slack formatters
```

## Adding New Channel

### 1. Create Channel Class

```typescript
// src/notification/channels/telegram.ts
import { BaseNotificationChannel } from '../base';
import type { NotificationPayload } from '../../types/notification';

export class TelegramChannel extends BaseNotificationChannel {
  name = 'telegram';
  priority = 80;
  
  constructor(private config: TelegramConfig) {
    super();
  }
  
  async send(notification: NotificationPayload): Promise<void> {
    try {
      // Format notification
      const message = this.formatNotification(notification);
      
      // Send to Telegram
      await fetch(`https://api.telegram.org/bot${this.config.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: this.config.chatId,
          text: message,
          parse_mode: 'Markdown',
        }),
      });
      
      this.log(`Sent to Telegram`);
    } catch (error: any) {
      await this.handleError(error, 'send');
      throw error;
    }
  }
  
  private formatNotification(notification: NotificationPayload): string {
    // Your formatting logic
    return 'Formatted message';
  }
}
```

### 2. Add Config Type

```typescript
// src/types/notification.ts
export interface TelegramChannelConfig {
  botToken: string;
  chatId: string;
}
```

### 3. Export Channel

```typescript
// src/notification/channels/index.ts
export { TelegramChannel } from './telegram';
```

### 4. Add Formatter (optional)

```typescript
// src/notification/formatters/telegram.ts
export function formatTelegramAttack(attack: AttackNotification): string {
  return `
*🚨 Attack Detected*

*Type:* ${attack.attackType}
*Severity:* ${attack.severity}
*IP:* \`${attack.attacker.ip}\`
*Endpoint:* \`${attack.target.endpoint}\`
  `.trim();
}
```

## Channel Interface

### Required Methods

```typescript
interface INotificationChannel {
  name: string;              // Unique identifier
  priority: number;          // Execution order (higher first)
  send(payload): Promise<void>;
}
```

### BaseNotificationChannel Helpers

```typescript
this.log(message, data?)           // Log activity
this.handleError(error, context)   // Handle errors
this.shouldHandle(notification)    // Filter notifications (optional)
```

## Notification Types

```typescript
type NotificationPayload =
  | { type: 'realtime_attack'; data: AttackNotification }
  | { type: 'attack_summary'; data: AttackSummary }
  | { type: 'detailed_report'; data: AttackSummary }
  | { type: 'attack_spike'; data: AttackSpikeAlert }
  | { type: 'metrics_summary'; data: MetricsSummary };
```

## Best Practices

### 1. Error Handling

Always use fail-open pattern:

```typescript
try {
  await sendToAPI();
} catch (error) {
  await this.handleError(error, 'send');
  throw error; // NotificationManager handles
}
```

### 2. Formatting

- Keep messages concise
- Use emojis sparingly
- Include key info first
- Link to details

### 3. Rate Limiting

NotificationManager handles global rate limiting.

Channel-specific limits (optional):

```typescript
class MyChannel extends BaseNotificationChannel {
  private lastSent = 0;
  
  async send(notification) {
    // Custom rate limit
    if (Date.now() - this.lastSent < 60000) {
      this.log('Rate limited, skipping');
      return;
    }
    
    // Send...
    this.lastSent = Date.now();
  }
}
```

### 4. Testing

```typescript
// Mock external API
const mockFetch = jest.fn();
global.fetch = mockFetch;

const channel = new MyChannel(config);
await channel.send(notification);

expect(mockFetch).toHaveBeenCalledWith(
  expectedUrl,
  expectedOptions
);
```

## Integration

### In Worker

```typescript
import { NotificationManager, EmailChannel, SlackChannel } from 'cloudflare-sentinel';

const manager = new NotificationManager();

// Add channels
manager.addChannel(new EmailChannel(emailConfig));
manager.addChannel(new SlackChannel(slackConfig));

// Use in Sentinel
const sentinel = new Sentinel({
  // ...
  notification: {
    enabled: true,
    manager,
  },
});
```

### Priority

Channels execute in priority order (highest first):
- EmailChannel: 100
- SlackChannel: 90
- Your channel: ?

## Examples

See existing channels:
- `channels/email.ts` - External API (Resend/SendGrid)
- `channels/slack.ts` - Webhook (Slack)

---

**Questions?** Open an issue or discussion.
