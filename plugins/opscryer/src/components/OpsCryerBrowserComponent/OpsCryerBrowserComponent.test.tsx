// SPDX-License-Identifier: Apache-2.0
import {
  buildClearDelegatedTokenMessage,
  buildDelegatedTokenMessage,
  buildEmbeddedOpscryerUrl,
  parseOpscryerIframeEvent,
  postClearDelegatedTokenToIframe,
  postDelegatedTokenToIframe,
  requestScopedOAuthToken,
  resolveOpscryerTargetOrigin,
  resolveSafeOpscryerUrl,
  sanitizeProviderSlug,
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

describe('Backstage OAuth2 PKCE delegated token bridge', () => {
  it('extracts strict http(s) targetOrigin and sanitizes provider slugs', () => {
    expect(
      resolveOpscryerTargetOrigin('https://opscryer.example.com:8443/hub?x=1'),
    ).toBe('https://opscryer.example.com:8443');
    expect(resolveOpscryerTargetOrigin('javascript:alert(1)')).toBe(
      'http://localhost:8088',
    );
    expect(sanitizeProviderSlug('  GitLab_Direct  ')).toBe('gitlab_direct');
    expect(sanitizeProviderSlug('bad/provider!')).toBe('gitlab');
  });

  it('refuses wildcard targetOrigin and posts strictly pinned delegated tokens', () => {
    const postMessage = jest.fn();
    expect(
      postDelegatedTokenToIframe(
        { postMessage },
        '*',
        'gitlab',
        'short-lived-pkce-token',
      ),
    ).toBe(false);
    expect(postMessage).not.toHaveBeenCalled();

    expect(
      postDelegatedTokenToIframe(
        { postMessage },
        'https://opscryer.example.com/hub',
        'gitlab',
        'short-lived-pkce-token',
      ),
    ).toBe(true);
    expect(postMessage).toHaveBeenCalledWith(
      buildDelegatedTokenMessage('gitlab', 'short-lived-pkce-token'),
      'https://opscryer.example.com',
    );

    expect(
      postClearDelegatedTokenToIframe(
        { postMessage },
        'https://opscryer.example.com',
        'gitlab',
      ),
    ).toBe(true);
    expect(postMessage).toHaveBeenLastCalledWith(
      buildClearDelegatedTokenMessage('gitlab'),
      'https://opscryer.example.com',
    );
  });

  it('accepts ready/authRequired only from exact expectedOrigin', () => {
    expect(
      parseOpscryerIframeEvent(
        { origin: 'https://evil.example.net', data: { type: 'opscryer:ready' } },
        'https://opscryer.example.com',
      ),
    ).toBeNull();
    expect(
      parseOpscryerIframeEvent(
        {
          origin: 'https://opscryer.example.com',
          data: { type: 'opscryer:authRequired', providers: ['gitlab', 'bad/x'] },
        },
        'https://opscryer.example.com',
      ),
    ).toEqual({ kind: 'authRequired', providers: ['gitlab'] });
  });

  it('requests scoped tokens cleanly for silent and interactive PKCE modes', async () => {
    const getAccessToken = jest.fn().mockResolvedValue('pkce-token-123');
    const tok = await requestScopedOAuthToken(
      { getAccessToken },
      ['read_api'],
      { optional: true },
    );
    expect(tok).toBe('pkce-token-123');
    expect(getAccessToken).toHaveBeenCalledWith(['read_api'], {
      optional: true,
    });

    const failingApi = {
      getAccessToken: jest.fn().mockRejectedValue(new Error('cancelled')),
    };
    await expect(
      requestScopedOAuthToken(failingApi, ['read_api'], { optional: false }),
    ).resolves.toBeNull();
  });
});
