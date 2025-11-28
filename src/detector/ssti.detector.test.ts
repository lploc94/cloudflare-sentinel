/**
 * SSTI Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { SSTIDetector } from './ssti.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('SSTIDetector', () => {
  const detector = new SSTIDetector();

  describe('Jinja2 (Python)', () => {
    it('should detect {{config}}', async () => {
      const request = new Request('https://example.com/page?name={{config}}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SSTI);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.engine).toBe('Jinja2');
    });

    it('should detect __class__ introspection', async () => {
      const request = new Request("https://example.com/page?name={{''.__class__.__mro__}}");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect __globals__ access', async () => {
      const request = new Request("https://example.com/page?x={{request.__class__.__globals__}}");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect __builtins__', async () => {
      const request = new Request("https://example.com/page?x={{config.__class__.__init__.__globals__['__builtins__']}}");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect __subclasses__', async () => {
      const request = new Request("https://example.com/page?x={{''.__class__.__mro__[2].__subclasses__()}}");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Twig (PHP)', () => {
    it('should detect _self.env access', async () => {
      const request = new Request('https://example.com/page?name={{_self.env.display("id")}}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Twig');
    });
  });

  describe('Freemarker (Java)', () => {
    it('should detect getClass() access', async () => {
      const request = new Request('https://example.com/page?name=${x.getClass().forName("java.lang.Runtime")}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Freemarker');
    });

    it('should detect Execute utility', async () => {
      const request = new Request('https://example.com/page?x=${freemarker.template.utility.Execute}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Velocity (Java)', () => {
    it('should detect $class.inspect', async () => {
      const request = new Request('https://example.com/page?x=$class.inspect("java.lang.Runtime")');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Velocity');
    });
  });

  describe('ERB (Ruby)', () => {
    it('should detect backtick execution', async () => {
      const request = new Request('https://example.com/page?name=<%= `id` %>');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('ERB');
    });

    it('should detect system() call', async () => {
      const request = new Request("https://example.com/page?x=<%= system('whoami') %>");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect eval() call', async () => {
      const request = new Request("https://example.com/page?x=<%= eval('1+1') %>");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Thymeleaf (Java/Spring)', () => {
    it('should detect T(java.lang.Runtime)', async () => {
      const request = new Request('https://example.com/page?x=${T(java.lang.Runtime).getRuntime().exec("id")}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Thymeleaf');
    });

    it('should detect ProcessBuilder', async () => {
      const request = new Request('https://example.com/page?x=${T(java.lang.ProcessBuilder)}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Smarty (PHP)', () => {
    it('should detect {php} tag', async () => {
      const request = new Request('https://example.com/page', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'content={php}echo "pwned";{/php}',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Smarty');
    });
  });

  describe('Expression Evaluation', () => {
    it('should detect ${7*7} probe', async () => {
      const request = new Request('https://example.com/page?x=${7*7}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Generic');
    });

    it('should detect {{7*7}} probe', async () => {
      const request = new Request('https://example.com/page?x={{7*7}}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect #{7*7} probe', async () => {
      // #{} is a URL fragment, need to encode it
      const request = new Request('https://example.com/page?x=' + encodeURIComponent('#{7*7}'));
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Java EL', () => {
    it('should detect Runtime.getRuntime()', async () => {
      const request = new Request('https://example.com/page?x=${Runtime.getRuntime().exec("id")}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.engine).toBe('Java EL');
    });

    it('should detect ProcessBuilder', async () => {
      const request = new Request('https://example.com/page?x=${new ProcessBuilder("cmd").start()}');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('POST Body', () => {
    it('should detect SSTI in JSON body', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ template: '{{config}}' }),
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('body.template');
    });

    it('should detect SSTI in form body', async () => {
      const request = new Request('https://example.com/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'message={{self.__class__}}',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('URL Encoding', () => {
    it('should detect URL-encoded SSTI', async () => {
      const encoded = encodeURIComponent('{{config}}');
      const request = new Request(`https://example.com/page?name=${encoded}`);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect double URL-encoded SSTI via POST', async () => {
      // Double encoding is better tested in body where no URL parsing occurs
      const encoded = encodeURIComponent(encodeURIComponent('{{config}}'));
      const request = new Request('https://example.com/page', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `name=${encoded}`,
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Safe Input', () => {
    it('should not detect normal text', async () => {
      const request = new Request('https://example.com/page?name=John');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect normal brackets', async () => {
      const request = new Request('https://example.com/page?data={name: "test"}');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect safe HTML', async () => {
      const request = new Request('https://example.com/page?content=<p>Hello</p>');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('ssti');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(92);
    });

    it('should exclude specified fields', async () => {
      const detector = new SSTIDetector({ excludeFields: ['template'] });
      const request = new Request('https://example.com/page?template={{config}}');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should provide static patterns', () => {
      expect(SSTIDetector.PATTERNS).toBeDefined();
      expect(SSTIDetector.PATTERNS.length).toBeGreaterThan(0);
    });
  });
});
