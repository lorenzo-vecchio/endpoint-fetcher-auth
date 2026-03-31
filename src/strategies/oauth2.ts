import type {
  OAuth2AuthConfig,
  OAuth2ClientCredentialsConfig,
  OAuth2DeviceCodeConfig,
  DeviceAuthorizationInfo,
  TokenStorage,
  HandlerContext,
} from '../types';

// ---------------------------------------------------------------------------
// PKCE utilities (exported for use in browser auth flows)
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically random PKCE code verifier (43–128 chars, base64url).
 *
 * @example
 * ```typescript
 * import { generateCodeVerifier, generateCodeChallenge, buildAuthorizationUrl } from 'endpoint-fetcher-auth';
 *
 * const verifier = generateCodeVerifier();
 * const challenge = await generateCodeChallenge(verifier);
 * sessionStorage.setItem('pkce_verifier', verifier);
 * window.location.href = buildAuthorizationUrl(config, challenge);
 * ```
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  (globalThis.crypto ?? crypto).getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Derives a PKCE code challenge from a code verifier using SHA-256.
 *
 * @param verifier - The code verifier produced by `generateCodeVerifier()`.
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await getSubtle().digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(digest));
}

/**
 * Builds the authorization URL for the Authorization Code + PKCE flow.
 *
 * @param authorizationEndpoint - The authorization endpoint URL.
 * @param clientId              - The OAuth2 client identifier.
 * @param redirectUri           - The registered redirect URI.
 * @param codeChallenge         - The PKCE code challenge.
 * @param scope                 - Space-separated scopes.
 * @param state                 - Optional CSRF state value.
 */
export function buildAuthorizationUrl(
  authorizationEndpoint: string,
  clientId: string,
  redirectUri: string,
  codeChallenge: string,
  scope?: string,
  state?: string,
): string {
  const url = new URL(authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (scope) url.searchParams.set('scope', scope);
  if (state) url.searchParams.set('state', state);
  return url.toString();
}

/**
 * Exchanges an authorization code for tokens (Authorization Code grant).
 *
 * @param tokenEndpoint  - The token endpoint URL.
 * @param clientId       - The OAuth2 client identifier.
 * @param code           - The authorization code from the redirect.
 * @param redirectUri    - The redirect URI used in the initial request.
 * @param codeVerifier   - The PKCE code verifier.
 * @param clientSecret   - Optional client secret.
 * @param fetchFn        - Optional custom fetch function.
 */
export async function exchangeCodeForToken(
  tokenEndpoint: string,
  clientId: string,
  code: string,
  redirectUri: string,
  codeVerifier: string,
  clientSecret?: string,
  fetchFn?: typeof fetch,
): Promise<{ accessToken: string; refreshToken?: string; expiresIn?: number }> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });
  if (clientSecret) body.set('client_secret', clientSecret);

  const fn = fetchFn ?? globalThis.fetch;
  const response = await fn(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function base64urlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function getSubtle(): SubtleCrypto {
  const subtle = (globalThis.crypto ?? (globalThis as any).webcrypto)?.subtle;
  if (!subtle) throw new Error('SubtleCrypto is not available. Requires Node.js >= 18 or a modern browser.');
  return subtle;
}

async function fetchClientCredentialsToken(
  config: OAuth2ClientCredentialsConfig,
  fetchFn: typeof fetch,
): Promise<{ accessToken: string; expiresIn?: number; refreshToken?: string }> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });
  if (config.scope) body.set('scope', config.scope);

  const response = await fetchFn(config.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    throw new Error(`OAuth2 token request failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in,
    refreshToken: data.refresh_token,
  };
}

async function refreshAccessToken(
  tokenEndpoint: string,
  clientId: string,
  refreshToken: string,
  clientSecret: string | undefined,
  fetchFn: typeof fetch,
): Promise<{ accessToken: string; expiresIn?: number; refreshToken?: string }> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: clientId,
    refresh_token: refreshToken,
  });
  if (clientSecret) body.set('client_secret', clientSecret);

  const response = await fetchFn(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    throw new Error(`OAuth2 token refresh failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in,
    refreshToken: data.refresh_token,
  };
}

async function runDeviceFlow(
  config: OAuth2DeviceCodeConfig,
  storage: TokenStorage,
  tokenKey: string,
  refreshTokenKey: string,
  tokenExpiry: { value: number | null },
  fetchFn: typeof fetch,
): Promise<void> {
  // Step 1: Request device code
  const body = new URLSearchParams({ client_id: config.clientId });
  if (config.scope) body.set('scope', config.scope);

  const deviceResp = await fetchFn(config.deviceAuthorizationEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!deviceResp.ok) {
    throw new Error(`Device authorization request failed: ${deviceResp.status}`);
  }

  const deviceData = await deviceResp.json();
  const info: DeviceAuthorizationInfo = {
    deviceCode: deviceData.device_code,
    userCode: deviceData.user_code,
    verificationUri: deviceData.verification_uri,
    verificationUriComplete: deviceData.verification_uri_complete,
    expiresIn: deviceData.expires_in ?? 1800,
    interval: deviceData.interval ?? 5,
  };

  config.onDeviceAuthorization(info);

  // Step 2: Poll for token
  const pollInterval = config.pollingInterval ?? (info.interval * 1000);
  const deadline = Date.now() + info.expiresIn * 1000;

  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, pollInterval));

    const pollBody = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      client_id: config.clientId,
      device_code: info.deviceCode,
    });

    const pollResp = await fetchFn(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: pollBody.toString(),
    });

    const pollData = await pollResp.json();

    if (pollData.error === 'authorization_pending' || pollData.error === 'slow_down') {
      continue;
    }

    if (!pollResp.ok || pollData.error) {
      throw new Error(`Device flow polling failed: ${pollData.error ?? pollResp.status}`);
    }

    storage.set(tokenKey, pollData.access_token);
    if (pollData.refresh_token) storage.set(refreshTokenKey, pollData.refresh_token);
    tokenExpiry.value = pollData.expires_in ? Date.now() + pollData.expires_in * 1000 : null;
    return;
  }

  throw new Error('Device authorization flow timed out');
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Creates a fetch wrapper that implements the OAuth2 authentication strategy.
 *
 * Supports three grant types:
 * - `client_credentials` — fully automatic; fetches and refreshes tokens without user interaction.
 * - `authorization_code` — uses the token in storage; call `setToken()` after completing the browser flow.
 * - `device_code` — initiates the device flow, polls for completion, then stores the token.
 *
 * @param config          OAuth2 strategy configuration.
 * @param storage         Token storage adapter.
 * @param tokenKey        Storage key for the access token.
 * @param refreshTokenKey Storage key for the refresh token.
 */
export function createOAuth2Fetch(
  config: OAuth2AuthConfig,
  storage: TokenStorage,
  tokenKey: string,
  refreshTokenKey: string,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  // Shared token expiry state across all endpoint requests
  const tokenExpiry: { value: number | null } = { value: null };
  // Tracks in-flight token acquisition to prevent duplicate requests
  let tokenPromise: Promise<void> | null = null;

  function isExpired(): boolean {
    return tokenExpiry.value !== null && Date.now() >= tokenExpiry.value;
  }

  async function ensureToken(fetchFn: typeof fetch): Promise<void> {
    if (config.grantType === 'client_credentials') {
      const existing = storage.get(tokenKey);
      if (existing && !isExpired()) return;

      if (!tokenPromise) {
        tokenPromise = fetchClientCredentialsToken(config, fetchFn).then(({ accessToken, expiresIn, refreshToken }) => {
          storage.set(tokenKey, accessToken);
          if (refreshToken) storage.set(refreshTokenKey, refreshToken);
          tokenExpiry.value = expiresIn ? Date.now() + expiresIn * 1000 : null;
        }).finally(() => { tokenPromise = null; });
      }
      await tokenPromise;
    } else if (config.grantType === 'device_code') {
      const existing = storage.get(tokenKey);
      if (existing && !isExpired()) return;

      if (!tokenPromise) {
        tokenPromise = runDeviceFlow(config, storage, tokenKey, refreshTokenKey, tokenExpiry, fetchFn)
          .finally(() => { tokenPromise = null; });
      }
      await tokenPromise;
    } else if (config.grantType === 'authorization_code') {
      const existing = storage.get(tokenKey);
      if (!existing) {
        config.onUnauthenticated?.();
        return;
      }

      // Attempt refresh if expired
      if (isExpired()) {
        const rt = storage.get(refreshTokenKey);
        if (rt) {
          try {
            const result = await refreshAccessToken(
              config.tokenEndpoint,
              config.clientId,
              rt,
              config.clientSecret,
              fetchFn,
            );
            storage.set(tokenKey, result.accessToken);
            if (result.refreshToken) storage.set(refreshTokenKey, result.refreshToken);
            tokenExpiry.value = result.expiresIn ? Date.now() + result.expiresIn * 1000 : null;
          } catch {
            // Refresh failed — continue with the existing (possibly expired) token
          }
        }
      }
    }
  }

  return (originalFetch: typeof fetch, _context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      await ensureToken(originalFetch);

      const token = storage.get(tokenKey);
      const headers = new Headers(init?.headers);
      if (token) headers.set('Authorization', `Bearer ${token}`);

      const response = await originalFetch(input, { ...init, headers });

      // On 401, try once more if we can refresh
      if (response.status === 401) {
        const rt = storage.get(refreshTokenKey);
        if (rt) {
          const clientSecret =
            config.grantType !== 'device_code'
              ? (config as OAuth2ClientCredentialsConfig).clientSecret
              : undefined;

          try {
            const result = await refreshAccessToken(
              config.tokenEndpoint,
              config.clientId,
              rt,
              clientSecret,
              originalFetch,
            );
            storage.set(tokenKey, result.accessToken);
            if (result.refreshToken) storage.set(refreshTokenKey, result.refreshToken);
            tokenExpiry.value = result.expiresIn ? Date.now() + result.expiresIn * 1000 : null;

            const retryHeaders = new Headers(init?.headers);
            retryHeaders.set('Authorization', `Bearer ${result.accessToken}`);
            return originalFetch(input, { ...init, headers: retryHeaders });
          } catch {
            // Fall through and return the 401 response
          }
        }
      }

      return response;
    };
  };
}
