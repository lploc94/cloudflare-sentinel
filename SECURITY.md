# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

### How to Report

If you discover a security vulnerability in Cloudflare Sentinel, please send an email to:

**lploc94@gmail.com**

### What to Include

Please include the following information:

1. **Type of vulnerability**
   - SQL injection bypass
   - XSS detection bypass
   - Rate limit bypass
   - Information disclosure
   - Other

2. **Steps to reproduce**
   - Detailed steps
   - Example payloads (sanitized if needed)
   - Environment details

3. **Impact assessment**
   - What data is at risk?
   - How severe is the issue?
   - Are there known exploits?

4. **Suggested fix** (if you have one)

### Example Report

```
Subject: [SECURITY] SQL Injection Detection Bypass

Type: Detection Bypass
Severity: High

Description:
The SQL injection detector can be bypassed using Unicode characters...

Steps to Reproduce:
1. Send request with payload: ...
2. Detection fails to trigger
3. Backend executes malicious query

Impact:
Attackers can bypass SQL injection protection and potentially
extract database contents.

Suggested Fix:
Add Unicode normalization before pattern matching.
```

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-3 days
  - High: 7-14 days
  - Medium: 14-30 days
  - Low: 30-90 days

### Disclosure Policy

- We follow **coordinated disclosure**
- Security fixes will be released ASAP
- CVE will be requested if applicable
- Credit given to reporter (if desired)
- Public disclosure after fix is released

## Security Best Practices

### Deployment

1. **Start with logging only**
   ```typescript
   new MultiLevelResolver({
     levels: [
       { maxScore: 100, actions: ['log'] },  // Log everything first
     ],
   })
   ```

2. **Monitor before blocking**
   - Review logs for false positives
   - Adjust thresholds gradually
   - Enable blocking when confident

3. **Use whitelist for trusted sources**
   ```typescript
   new WhitelistDetector({
     ips: ['1.2.3.4'],
     ipRanges: ['10.0.0.0/8'],
   })
   ```

4. **Protect origin server**
   - Use Cloudflare Tunnel (recommended)
   - Firewall origin to only accept Cloudflare IPs

5. **Regular updates**
   - Keep Sentinel updated
   - Review security advisories

### Configuration

1. **Use secrets for sensitive data**
   ```bash
   wrangler secret put SLACK_WEBHOOK
   ```

2. **Environment-specific thresholds**
   ```typescript
   const thresholds = env.ENVIRONMENT === 'production' 
     ? STRICT 
     : RELAXED;
   ```

3. **Multi-level response**
   ```typescript
   levels: [
     { maxScore: 30, actions: ['increment'] },
     { maxScore: 60, actions: ['log', 'escalate'] },
     { maxScore: 100, actions: ['block', 'notify'] },
   ]
   ```

### Monitoring

1. **Set up notifications** - Alert on high-severity attacks
2. **Use Analytics Engine** - Track attack patterns
3. **Review escalation data** - Identify repeat offenders

## Security Updates

Security updates will be announced via:
- GitHub Security Advisories
- Release notes (marked as **Security**)
- Email notification (if subscribed)

## Bug Bounty

Currently, we do not have a formal bug bounty program. However:
- We deeply appreciate security researchers
- Contributors will be credited in releases
- Significant findings will be recognized

---

**Thank you for helping keep Cloudflare Sentinel secure!** 🔒
