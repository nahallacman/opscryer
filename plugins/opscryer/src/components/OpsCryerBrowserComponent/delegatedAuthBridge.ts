// SPDX-License-Identifier: Apache-2.0
/**
 * Pure Backstage OAuth2 PKCE <-> OpsCryer iframe postMessage token bridge helpers.
 *
 * Security invariants:
 * - Never sends tokens with wildcard '*' targetOrigin; strictly pins targetOrigin
 *   to the validated http(s) origin of the embedded OpsCryer iframe.
 * - Rejects incoming iframe handshake events whose origin does not exactly match
 *   expectedOrigin.
 * - Keeps tokens short-lived and request/session-scoped inside OpsCryer (cleared
 *   immediately via opscryer:clearDelegatedToken on disconnect).
 */

export const OPSCRYER_READY_EVENT = 'opscryer:ready';
export const OPSCRYER_AUTH_REQUIRED_EVENT = 'opscryer:authRequired';
export const OPSCRYER_SET_TOKEN_EVENT = 'opscryer:setDelegatedToken';
export const OPSCRYER_CLEAR_TOKEN_EVENT = 'opscryer:clearDelegatedToken';
export const DEFAULT_OPSCRYER_URL = 'http://localhost:8088';
export const DEFAULT_OAUTH_PROVIDER = 'gitlab';
export const DEFAULT_OAUTH_SCOPES: readonly string[] = ['read_api'];

const PROVIDER_SLUG_RE = /^[a-z0-9_.-]{1,64}$/;

export interface OAuthTokenApiLike {
  getAccessToken(
    scope?: string | string[],
    options?: {
      optional?: boolean;
      instantPopup?: boolean;
    },
  ): Promise<string>;
}

export interface DelegatedTokenPostMessage {
  type: typeof OPSCRYER_SET_TOKEN_EVENT;
  provider: string;
  token: string;
  source: 'backstage-oauth-pkce';
}

export interface ClearDelegatedTokenPostMessage {
  type: typeof OPSCRYER_CLEAR_TOKEN_EVENT;
  provider?: string;
  source: 'backstage-oauth-pkce';
}

export type OpscryerIframeEvent =
  | { kind: 'ready' }
  | { kind: 'authRequired'; providers: string[] };

export function resolveOpscryerTargetOrigin(
  rawUrl: string | undefined,
): string {
  const candidate = (rawUrl ?? '').trim();
  const fallbackOrigin = new URL(DEFAULT_OPSCRYER_URL).origin;
  if (!candidate) {
    return fallbackOrigin;
  }
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.origin;
    }
  } catch {
    return fallbackOrigin;
  }
  return fallbackOrigin;
}

export function sanitizeProviderSlug(raw: string | undefined): string {
  const cleaned = String(raw ?? '')
    .trim()
    .toLowerCase();
  if (!PROVIDER_SLUG_RE.test(cleaned)) {
    return DEFAULT_OAUTH_PROVIDER;
  }
  return cleaned;
}

export function buildDelegatedTokenMessage(
  provider: string,
  token: string,
): DelegatedTokenPostMessage | null {
  const cleanProv = String(provider ?? '')
    .trim()
    .toLowerCase();
  const cleanTok = String(token ?? '').trim();
  if (!PROVIDER_SLUG_RE.test(cleanProv) || !cleanTok) {
    return null;
  }
  return {
    type: OPSCRYER_SET_TOKEN_EVENT,
    provider: cleanProv,
    token: cleanTok,
    source: 'backstage-oauth-pkce',
  };
}

export function buildClearDelegatedTokenMessage(
  provider?: string,
): ClearDelegatedTokenPostMessage {
  const cleanProv = String(provider ?? '')
    .trim()
    .toLowerCase();
  if (cleanProv && PROVIDER_SLUG_RE.test(cleanProv)) {
    return {
      type: OPSCRYER_CLEAR_TOKEN_EVENT,
      provider: cleanProv,
      source: 'backstage-oauth-pkce',
    };
  }
  return {
    type: OPSCRYER_CLEAR_TOKEN_EVENT,
    source: 'backstage-oauth-pkce',
  };
}

export function parseOpscryerIframeEvent(
  event: { origin?: string; data?: unknown } | null | undefined,
  expectedOrigin: string,
): OpscryerIframeEvent | null {
  if (!event || !expectedOrigin || expectedOrigin === '*') {
    return null;
  }
  if (event.origin !== expectedOrigin) {
    return null;
  }
  const d = event.data as Record<string, unknown> | null | undefined;
  if (!d || typeof d !== 'object') {
    return null;
  }
  if (d.type === OPSCRYER_READY_EVENT) {
    return { kind: 'ready' };
  }
  if (d.type === OPSCRYER_AUTH_REQUIRED_EVENT) {
    const rawProviders = Array.isArray(d.providers) ? d.providers : [];
    const providers = rawProviders
      .map(p => String(p ?? '').trim().toLowerCase())
      .filter(p => PROVIDER_SLUG_RE.test(p));
    return { kind: 'authRequired', providers };
  }
  return null;
}

export async function requestScopedOAuthToken(
  oauthApi: OAuthTokenApiLike | null | undefined,
  scopes: readonly string[] = DEFAULT_OAUTH_SCOPES,
  options: { optional: boolean } = { optional: true },
): Promise<string | null> {
  if (!oauthApi || typeof oauthApi.getAccessToken !== 'function') {
    return null;
  }
  try {
    const raw = await oauthApi.getAccessToken([...scopes], {
      optional: Boolean(options.optional),
    });
    const clean = String(raw ?? '').trim();
    return clean || null;
  } catch {
    return null;
  }
}

export function postDelegatedTokenToIframe(
  iframeWindow: Pick<Window, 'postMessage'> | null | undefined,
  targetOrigin: string,
  provider: string,
  token: string,
): boolean {
  if (!iframeWindow || typeof iframeWindow.postMessage !== 'function') {
    return false;
  }
  if (!targetOrigin || targetOrigin === '*') {
    return false;
  }
  let normalizedOrigin: string;
  try {
    const parsed = new URL(targetOrigin);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    normalizedOrigin = parsed.origin;
  } catch {
    return false;
  }
  const message = buildDelegatedTokenMessage(provider, token);
  if (!message) {
    return false;
  }
  iframeWindow.postMessage(message, normalizedOrigin);
  return true;
}

export function postClearDelegatedTokenToIframe(
  iframeWindow: Pick<Window, 'postMessage'> | null | undefined,
  targetOrigin: string,
  provider?: string,
): boolean {
  if (!iframeWindow || typeof iframeWindow.postMessage !== 'function') {
    return false;
  }
  if (!targetOrigin || targetOrigin === '*') {
    return false;
  }
  let normalizedOrigin: string;
  try {
    const parsed = new URL(targetOrigin);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    normalizedOrigin = parsed.origin;
  } catch {
    return false;
  }
  iframeWindow.postMessage(
    buildClearDelegatedTokenMessage(provider),
    normalizedOrigin,
  );
  return true;
}
