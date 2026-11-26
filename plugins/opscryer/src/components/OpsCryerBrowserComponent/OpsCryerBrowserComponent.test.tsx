// SPDX-License-Identifier: Apache-2.0
import {
  buildEmbeddedOpscryerUrl,
  resolveSafeOpscryerUrl,
} from './OpsCryerBrowserComponent';

describe('resolveSafeOpscryerUrl', () => {
  it('falls back to localhost default when empty or undefined', () => {
    expect(resolveSafeOpscryerUrl(undefined)).toBe('http://localhost:8088');
    expect(resolveSafeOpscryerUrl('')).toBe('http://localhost:8088');
    expect(resolveSafeOpscryerUrl('   ')).toBe('http://localhost:8088');
  });

  it('allows valid http and https URLs with whitespace trimmed', () => {
    expect(resolveSafeOpscryerUrl('  https://opscryer.example.com/hub  ')).toBe(
      'https://opscryer.example.com/hub',
    );
    expect(resolveSafeOpscryerUrl('http://opscryer.example.com:8088')).toBe(
      'http://opscryer.example.com:8088/',
    );
  });

  it('rejects non-http(s) schemes and malformed URLs', () => {
    expect(resolveSafeOpscryerUrl('javascript:alert(1)')).toBe(
      'http://localhost:8088',
    );
    expect(resolveSafeOpscryerUrl('data:text/html,<h1>xss</h1>')).toBe(
      'http://localhost:8088',
    );
    expect(resolveSafeOpscryerUrl('ftp://opscryer.example.com')).toBe(
      'http://localhost:8088',
    );
    expect(resolveSafeOpscryerUrl('not a valid url')).toBe(
      'http://localhost:8088',
    );
  });
});

describe('buildEmbeddedOpscryerUrl', () => {
  it('appends preset=iframe by default for compact iframe embedding', () => {
    expect(buildEmbeddedOpscryerUrl('https://opscryer.example.com')).toBe(
      'https://opscryer.example.com/?preset=iframe',
    );
  });

  it('preserves explicit preset or embed parameters without duplicating them', () => {
    expect(
      buildEmbeddedOpscryerUrl('https://opscryer.example.com/?preset=minimal'),
    ).toBe('https://opscryer.example.com/?preset=minimal');
    expect(
      buildEmbeddedOpscryerUrl('https://opscryer.example.com/?embed=1'),
    ).toBe('https://opscryer.example.com/?embed=1');
  });
});
