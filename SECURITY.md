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

1. **Start with `log_only` mode**
   ```typescript
   attackLimits: {
     sql_injection: {
       limit: 100,
       period: 3600,
       action: 'log_only'  // Monitor first!
     }
   }
   ```

2. **Monitor for false positives**
   - Check `/__sentinel/metrics` regularly
   - Review Analytics Engine data
   - Adjust confidence thresholds

3. **Use whitelist for trusted sources**
   ```typescript
   whitelist: {
     ips: ['1.2.3.4'],
     userAgents: ['TrustedBot/1.0']
   }
   ```

4. **Protect origin server**
   - Use Cloudflare Tunnel (recommended)
   - Firewall origin to only accept Cloudflare IPs
   - Validate `CF-Connecting-IP` header

5. **Regular updates**
   - Keep Sentinel updated
   - Review security advisories
   - Update detector patterns

### Configuration

1. **Don't expose metrics publicly**
   ```toml
   # Protect /__sentinel/metrics with:
   # - Cloudflare Zero Trust
   # - Service tokens
   # - IP whitelist
   ```

2. **Use environment-specific configs**
   ```typescript
   const isProd = env.ENVIRONMENT === 'production';
   
   attackLimits: {
     sql_injection: {
       limit: isProd ? 1 : 100,
       action: isProd ? 'block' : 'log_only'
     }
   }
   ```

3. **Enable all security features**
   ```typescript
   {
     enableBehaviorTracking: true,
     enableEarlyBlockCheck: true,
     enableAnalytics: true,
     enableD1: true
   }
   ```

### Monitoring

1. **Set up alerts**
   - High-severity attacks
   - Unusual traffic patterns
   - Many blocked requests

2. **Review logs regularly**
   ```sql
   -- Check blocked IPs
   SELECT ip_address, COUNT(*) 
   FROM security_events 
   WHERE blocked = 1 
   GROUP BY ip_address 
   ORDER BY COUNT(*) DESC;
   ```

3. **Analyze attack trends**
   - New attack patterns
   - Targeted endpoints
   - Geographic distribution

## Known Limitations

See [README.md - Limitations](README.md#-limitations) for:
- False positive scenarios
- Attack types not covered
- Performance constraints
- Bypass techniques

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
