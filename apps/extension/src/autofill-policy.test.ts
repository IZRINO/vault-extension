import { describe, expect, it } from 'vitest';
import { loginUrisMatch, sameSite, uriMatches, validateGroups, webUrl } from './autofill-policy';

describe('autofill site boundaries', () => {
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
