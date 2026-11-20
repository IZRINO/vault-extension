import { describe, expect, it } from 'vitest';
import { loginUrisMatch, resolveSiteFlags, sameSite, siteRuleMatches, siteRulesFor, uriMatches, validateGroups, validateSiteRule, webUrl } from './autofill-policy';

describe('autofill site boundaries', () => {
  it('combines exact and wildcard restrictions without an exception that enables a disabled function', () => {
    const exact = { inlineDisabled: true, saveDisabled: false, passkeyDisabled: false };
    const wildcard = { inlineDisabled: false, saveDisabled: true, passkeyDisabled: true };
    const sites = {
      'https://login.example.com:8443': exact,
      'https://*.example.com:8443': wildcard,
      'https://*.login.example.com:8443': { inlineDisabled: true, saveDisabled: false, passkeyDisabled: false },
    };
    const site = webUrl('https://login.example.com:8443/form');
    expect(siteRuleMatches('https://*.example.com:8443', site)).toBe(true);
    expect(siteRuleMatches('https://*.login.example.com:8443', site)).toBe(false);
    expect(siteRuleMatches('https://*.example.com', site)).toBe(false);
    expect(siteRulesFor(sites, site)).toMatchObject({
      exact, wildcardRules: [
        { rule: 'https://*.example.com:8443', flags: wildcard },
        { rule: 'https://*.login.example.com:8443', flags: sites['https://*.login.example.com:8443'] },
      ],
      effective: { inlineDisabled: true, saveDisabled: true, passkeyDisabled: true },
    });
    expect(resolveSiteFlags(sites, webUrl('https://eu.login.example.com:8443/'))).toEqual({
      inlineDisabled: true, saveDisabled: true, passkeyDisabled: true,
    });
    for (const target of ['https://example.com:8443', 'https://login.example.com', 'http://login.example.com:8443',
      'https://not-example.com:8443', 'https://login.example.com.invalid:8443']) {
      expect(resolveSiteFlags(sites, webUrl(target))).toEqual({ inlineDisabled: false, saveDisabled: false, passkeyDisabled: false });
    }
  });

  it('accepts canonical subdomain rules within a registrable suffix and bounds them to one scheme and port', () => {
    expect(validateSiteRule('https://*.alice.github.io:8443')).toBe('https://*.alice.github.io:8443');
    expect(validateSiteRule('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
    for (const invalid of [
      'https://*.github.io', 'https://*.co.uk', 'https://*.*.example.com', 'https://other*.example.com',
      'http://*.localhost', 'http://*.127.0.0.1:8080', 'https://*.nas.lan', 'https://*.example.com/path',
      'https://*.example.com:443', 'https://*.example.com#fragment', 'https://*.example.com.',
      'https://user@*.example.com', 'file://*.example.com', 'https://*.example.com:*',
    ]) expect(() => validateSiteRule(invalid)).toThrow();
  });
  it('honors a page exclusion before other URIs on the same account', () => {
    const uris = [{ uri: 'https://accounts.example.com' },
      { uri: 'https://settings.example.com/no-fill', matchRule: 'never' }];
    expect(loginUrisMatch(uris, webUrl('https://settings.example.com/no-fill?step=2#next'), [])).toBe(false);
    expect(loginUrisMatch(uris, webUrl('https://settings.example.com/profile'), [])).toBe(true);
  });
  it('supports the configured Apple and JD domain groups only on the same scheme and port', () => {
    expect(sameSite(webUrl('https://apple.com'), webUrl('https://www.icloud.com'))).toBe(true);
    expect(sameSite(webUrl('https://www.jd.com'), webUrl('https://3.cn'))).toBe(true);
    expect(sameSite(webUrl('https://www.jd.com'), webUrl('https://3.cn:8443'))).toBe(false);
  });
  it('uses private public suffixes and never matches deceptive lookalikes or HTTP downgrades', () => {
    const saved = { uri: 'https://github.com/login' };
    expect(uriMatches(saved, webUrl('https://github.com/settings'))).toBe(true);
    expect(uriMatches(saved, webUrl('https://github.com.evil.test/login'))).toBe(false);
    expect(uriMatches(saved, webUrl('http://github.com'))).toBe(false);
    expect(uriMatches({ uri: 'https://alice.github.io' }, webUrl('https://bob.github.io'))).toBe(false);
    expect(uriMatches({ uri: 'https://bank.example.co.uk' }, webUrl('https://phish.co.uk'))).toBe(false);
    expect(uriMatches({ uri: 'https://alice.blogspot.com' }, webUrl('https://bob.blogspot.com'))).toBe(false);
  });
  it('isolates localhost, IPv4, IPv6 and private services by scheme, host and port for every match rule', () => {
    for (const host of ['localhost', '127.0.0.1', '192.168.1.9', '[::1]', 'nas.local']) {
      for (const matchRule of ['base_domain', 'host', 'starts_with', 'exact', 'regex']) {
        expect(uriMatches({ uri: `http://${host}:8080/a`, matchRule }, webUrl(`http://${host}:9000/a`))).toBe(false);
      }
      expect(sameSite(webUrl(`http://${host}:8080`), webUrl(`http://${host}:9000`))).toBe(false);
      expect(uriMatches({ uri: `http://${host}:8080/a`, matchRule: 'exact' }, webUrl(`http://${host}:8080/b`))).toBe(false);
    }
  });
  it('honors never, exact and prefix boundaries and validates custom groups', () => {
    const target = webUrl('https://login.example.com/login');
    expect(uriMatches({ uri: 'https://login.example.com', matchRule: 'never' }, target)).toBe(false);
    expect(uriMatches({ uri: target.href, matchRule: 'exact' }, target)).toBe(true);
    expect(uriMatches({ uri: 'https://example.com', matchRule: 'starts_with' }, webUrl('https://example.com.evil.test'))).toBe(false);
    expect(uriMatches({ uri: '^https://login\\.example\\.com/.*$', matchRule: 'regex' }, target)).toBe(true);
    expect(uriMatches({ uri: '^https://login\\.example\\.com/.*$', matchRule: 'regex' }, webUrl('https://login.example.com.evil.test/login'))).toBe(false);
    expect(uriMatches({ uri: '(a+)+$', matchRule: 'regex' }, webUrl('https://example.com/' + 'a'.repeat(1000) + '!'))).toBe(false);
    expect(uriMatches({ uri: '.*', matchRule: 'regex' }, webUrl('http://server.lan:3000'))).toBe(false);
    expect(sameSite(webUrl('https://login.live.com'), webUrl('https://account.microsoft.com'))).toBe(true);
    const groups = validateGroups([['example.com', 'example.net']]);
    expect(sameSite(webUrl('https://example.com'), webUrl('https://example.net'), groups)).toBe(true);
    for (const group of [[['com', 'example.net']], [['github.io', 'example.net']], [['localhost', 'example.com']], [['example.com:443', 'example.net']]]) {
      expect(() => validateGroups(group)).toThrow();
    }
  });
});
