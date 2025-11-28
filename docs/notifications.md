# Notifications

Send alerts when attacks are detected.

## Slack Notifications

Use `NotifyHandler` with Slack webhook:

```typescript
import { SentinelPipeline, NotifyHandler } from 'cloudflare-sentinel';

const pipeline = SentinelPipeline.sync([...])
  .score(new MaxScoreAggregator())
  .resolve(new MultiLevelResolver({
    levels: [
      { maxScore: 60, actions: ['log'] },
      { maxScore: 100, actions: ['block', 'notify'] },  // notify on high score
    ],
  }))
  .on('notify', new NotifyHandler({
    webhookUrl: env.SLACK_WEBHOOK,
  }));
```

### wrangler.toml

```toml
[vars]
SLACK_WEBHOOK = "https://hooks.slack.com/services/xxx/yyy/zzz"
```

Or use secrets:
```bash
wrangler secret put SLACK_WEBHOOK
```

## Threshold-Based Alerts

Configure when to send notifications using `MultiLevelResolver`:

```typescript
new MultiLevelResolver({
  levels: [
    { maxScore: 30, actions: ['increment'] },           // Low: silent
    { maxScore: 60, actions: ['log'] },                 // Medium: log only
    { maxScore: 100, actions: ['block', 'notify'] },    // High: block + alert
  ],
})
```

## Custom Notification Handler

Create a custom handler for other services:

```typescript
import type { Action, HandlerContext } from 'cloudflare-sentinel';

class EmailHandler implements IActionHandler {
  type = 'notify';

  constructor(private config: { apiKey: string; to: string }) {}

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'sentinel@yourdomain.com',
        to: this.config.to,
        subject: `🚨 Attack Detected: ${action.data?.message}`,
        text: JSON.stringify(action.data, null, 2),
      }),
    });
  }
}

// Register
pipeline.on('notify', new EmailHandler({
  apiKey: env.RESEND_API_KEY,
  to: 'admin@yourdomain.com',
}));
```

## Best Practices

1. **Don't notify on every request** - Use thresholds
2. **Rate limit notifications** - Prevent spam during attacks
3. **Use secrets** - Never commit webhooks to git
4. **Test first** - Trigger a test attack to verify

---

**Questions?** Open an issue on GitHub.
