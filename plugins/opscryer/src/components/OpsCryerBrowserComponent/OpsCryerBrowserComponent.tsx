// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Typography,
} from '@material-ui/core';
import OpenInNewIcon from '@material-ui/icons/OpenInNew';
import { ContentHeader, InfoCard } from '@backstage/core-components';
import {
  useApi,
  useApiHolder,
  configApiRef,
  gitlabAuthApiRef,
} from '@backstage/core-plugin-api';
import {
  DEFAULT_OAUTH_PROVIDER,
  DEFAULT_OAUTH_SCOPES,
  DEFAULT_OPSCRYER_URL,
  OAuthTokenApiLike,
  parseOpscryerIframeEvent,
  postClearDelegatedTokenToIframe,
  postDelegatedTokenToIframe,
  requestScopedOAuthToken,
  resolveOpscryerTargetOrigin,
  sanitizeProviderSlug,
} from './delegatedAuthBridge';

export {
  buildClearDelegatedTokenMessage,
  buildDelegatedTokenMessage,
  parseOpscryerIframeEvent,
  postClearDelegatedTokenToIframe,
  postDelegatedTokenToIframe,
  requestScopedOAuthToken,
  resolveOpscryerTargetOrigin,
  sanitizeProviderSlug,
} from './delegatedAuthBridge';

export function resolveSafeOpscryerUrl(rawUrl: string | undefined): string {
  const candidate = (rawUrl ?? '').trim();
  if (!candidate) {
    return DEFAULT_OPSCRYER_URL;
  }
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.toString();
    }
  } catch {
    return DEFAULT_OPSCRYER_URL;
  }
  return DEFAULT_OPSCRYER_URL;
}

export function buildEmbeddedOpscryerUrl(
  rawUrl: string | undefined,
  preset: string = 'iframe',
): string {
  const safeBase = resolveSafeOpscryerUrl(rawUrl);
  try {
    const parsed = new URL(safeBase);
    if (!parsed.searchParams.has('preset') && !parsed.searchParams.has('embed')) {
      parsed.searchParams.set('preset', preset);
    }
    return parsed.toString();
  } catch {
    return safeBase;
  }
}

export const OpsCryerBrowserComponent = () => {
  const configApi = useApi(configApiRef);
  const apiHolder = useApiHolder();
  const iframeRef = useRef<HTMLIFrameElement | null>(null);

  const opscryerConfigs =
    configApi.getOptionalConfigArray('integrations.opscryer') ?? [];
  const primaryCfg = opscryerConfigs[0];
  const opscryerUrl = resolveSafeOpscryerUrl(
    primaryCfg?.getOptionalString('baseUrl'),
  );
  const targetOrigin = useMemo(
    () => resolveOpscryerTargetOrigin(opscryerUrl),
    [opscryerUrl],
  );
  const oauthProvider = sanitizeProviderSlug(
    primaryCfg?.getOptionalString('oauthProvider') ?? DEFAULT_OAUTH_PROVIDER,
  );
  const oauthScopes = useMemo(() => {
    const configured = primaryCfg?.getOptionalStringArray('oauthScopes');
    return configured && configured.length > 0
      ? configured
      : [...DEFAULT_OAUTH_SCOPES];
  }, [primaryCfg]);
  const oauthApi = apiHolder.get(gitlabAuthApiRef) as
    | OAuthTokenApiLike
    | undefined;

  const embedUrl = buildEmbeddedOpscryerUrl(opscryerUrl, 'iframe');
  const [authStatus, setAuthStatus] = useState<
    'idle' | 'connected' | 'auth_required' | 'unavailable'
  >(oauthApi ? 'idle' : 'unavailable');
  const [requiredProviders, setRequiredProviders] = useState<string[]>([]);

  const syncDelegatedToken = useCallback(
    async (interactive: boolean) => {
      if (!oauthApi) {
        setAuthStatus('unavailable');
        return false;
      }
      const token = await requestScopedOAuthToken(oauthApi, oauthScopes, {
        optional: !interactive,
      });
      if (!token) {
        if (interactive) {
          setAuthStatus('auth_required');
        }
        return false;
      }
      const posted = postDelegatedTokenToIframe(
        iframeRef.current?.contentWindow,
        targetOrigin,
        oauthProvider,
        token,
      );
      if (posted) {
        setAuthStatus('connected');
        setRequiredProviders([]);
      }
      return posted;
    },
    [oauthApi, oauthProvider, oauthScopes, targetOrigin],
  );

  const handleDisconnectOAuth = useCallback(() => {
    postClearDelegatedTokenToIframe(
      iframeRef.current?.contentWindow,
      targetOrigin,
      oauthProvider,
    );
    setAuthStatus(oauthApi ? 'idle' : 'unavailable');
  }, [oauthApi, oauthProvider, targetOrigin]);

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const parsed = parseOpscryerIframeEvent(event, targetOrigin);
      if (!parsed) {
        return;
      }
      if (parsed.kind === 'ready') {
        void syncDelegatedToken(false);
      } else if (parsed.kind === 'authRequired') {
        setRequiredProviders(parsed.providers);
        setAuthStatus('auth_required');
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [syncDelegatedToken, targetOrigin]);

  const statusChipLabel =
    authStatus === 'connected'
      ? `OAuth2 PKCE delegated (${oauthProvider})`
      : authStatus === 'auth_required'
      ? `Sign-in required (${requiredProviders.join(', ') || oauthProvider})`
      : authStatus === 'unavailable'
      ? 'Read-only (OAuthApi not registered)'
      : 'Read-only integration';

  return (
    <Box flexGrow={1} p={3} width="100%">
      <ContentHeader title="OpsCryer Spatial Browser" />
      <Box mt={2}>
        <InfoCard title="OpsCryer">
          <CardContent>
            <Typography variant="body1">
              Embedded OpsCryer spatial browser ({opscryerUrl}). Displays the
              SpatialGraphContract v1 knowledge graph synced from the Central
              Brain via the OpsCryer bridge.
            </Typography>
          </CardContent>
        </InfoCard>
      </Box>
      <Box mt={2}>
        <Card>
          <CardHeader
            title="Spatial Browser"
            subheader={`Loading from ${opscryerUrl}`}
            action={
              <Box display="flex" alignItems="center" style={{ gap: 8 }}>
                {oauthApi && authStatus !== 'connected' && (
                  <Button
                    size="small"
                    variant="outlined"
                    color="primary"
                    onClick={() => void syncDelegatedToken(true)}
                  >
                    Connect OAuth (PKCE)
                  </Button>
                )}
                {oauthApi && authStatus === 'connected' && (
                  <Button
                    size="small"
                    variant="outlined"
                    color="default"
                    onClick={handleDisconnectOAuth}
                  >
                    Disconnect OAuth
                  </Button>
                )}
                <Button
                  size="small"
                  color="primary"
                  startIcon={<OpenInNewIcon />}
                  href={opscryerUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Launch in new tab
                </Button>
              </Box>
            }
          />
          <CardContent>
            <iframe
              ref={iframeRef}
              src={embedUrl}
              title="OpsCryer Spatial Browser"
              onLoad={() => void syncDelegatedToken(false)}
              style={{
                width: '100%',
                height: '80vh',
                border: 'none',
                display: 'block',
              }}
              sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
            />
          </CardContent>
        </Card>
      </Box>
      <Box mt={2}>
        <Chip
          label={statusChipLabel}
          color={authStatus === 'connected' ? 'primary' : 'default'}
          size="small"
          variant="outlined"
        />
      </Box>
      <Box mt={2}>
        <Typography variant="caption" color="textSecondary">
          OpsCryer is an independent service. When Backstage OAuthApi is
          configured, short-lived PKCE access tokens are bridged strictly to{' '}
          {targetOrigin} via postMessage without storing secrets on the server.
        </Typography>
      </Box>
    </Box>
  );
};
