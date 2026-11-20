// SPDX-License-Identifier: Apache-2.0
import { resolveSafeOpscryerUrl } from './OpsCryerBrowserComponent';

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
