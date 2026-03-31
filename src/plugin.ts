import { createPlugin } from 'endpoint-fetcher';
import type { AuthPluginConfig, TokenStorage, HandlerContext } from './types';
import { MemoryTokenStorage } from './storage/memory';
import { createJwtFetch } from './strategies/jwt';
import { createOAuth2Fetch } from './strategies/oauth2';
import { createApiKeyFetch } from './strategies/api-key';
import { createBasicFetch } from './strategies/basic';
import { createBearerFetch } from './strategies/bearer';
import { createHmacFetch } from './strategies/hmac';
import { createDigestFetch } from './strategies/digest';
import { createCustomFetch } from './strategies/custom';

// ---------------------------------------------------------------------------
// Strategy dispatch
// ---------------------------------------------------------------------------

type StrategyFetchCreator = (
  originalFetch: typeof fetch,
  context: HandlerContext,
) => typeof fetch;

function buildStrategyCreator(
  config: AuthPluginConfig,
  storage: TokenStorage,
  tokenKey: string,
  refreshTokenKey: string,
): StrategyFetchCreator {
  switch (config.strategy) {
    case 'jwt':
      return createJwtFetch(config, storage, tokenKey, refreshTokenKey);
    case 'oauth2':
      return createOAuth2Fetch(config, storage, tokenKey, refreshTokenKey);
    case 'api-key':
      return createApiKeyFetch(config);
    case 'basic':
      return createBasicFetch(config);
    case 'bearer':
      return createBearerFetch(config, storage, config.tokenStorageKey ?? tokenKey);
    case 'hmac':
      return createHmacFetch(config);
    case 'digest':
      return createDigestFetch(config);
    case 'custom':
      return createCustomFetch(config);
  }
}

// ---------------------------------------------------------------------------
// Storage resolution helper
// ---------------------------------------------------------------------------

function resolveStorage(config: AuthPluginConfig): TokenStorage {
  const c = config as Record<string, unknown>;
  return (c['storage'] as TokenStorage | undefined) ?? new MemoryTokenStorage();
}

// ---------------------------------------------------------------------------
// Auth plugin
// ---------------------------------------------------------------------------

/**
 * Authentication plugin for `endpoint-fetcher`.
 *
 * Supports eight strategies via a discriminated-union config:
 * `'jwt'`, `'oauth2'`, `'api-key'`, `'basic'`, `'bearer'`, `'hmac'`,
 * `'digest'`, and `'custom'`.
 *
 * The plugin mutates request headers via `handlerWrapper` — it does **not**
 * wrap the response type, so your declared output type stays clean.
 *
 * Plugin methods are accessible at `client.plugins.auth`:
 * - `setToken(token)` — store an access token
 * - `getToken()` — retrieve the current access token
 * - `setRefreshToken(token)` — store a refresh token
 * - `getRefreshToken()` — retrieve the current refresh token
 * - `logout()` — clear all stored tokens
 * - `isAuthenticated()` — check if an access token is present
 *
 * @param config - Authentication strategy configuration (discriminated by `strategy`).
 * @returns Plugin options for `createApiClient`.
 *
 * @example JWT strategy
 * ```typescript
 * import { createApiClient, get } from 'endpoint-fetcher';
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient(
 *   { me: get<void, { id: number; email: string }>('/me') },
 *   {
 *     baseUrl: 'https://api.example.com',
 *     plugins: [
 *       auth({
 *         strategy: 'jwt',
 *         token: localStorage.getItem('access_token') ?? undefined,
 *         refreshCallback: async (rt) => {
 *           const res = await fetch('/auth/refresh', {
 *             method: 'POST',
 *             body: JSON.stringify({ refresh_token: rt }),
 *           });
 *           const data = await res.json();
 *           return { token: data.access_token, refreshToken: data.refresh_token };
 *         },
 *       }),
 *     ] as const,
 *   },
 * );
 *
 * const user = await api.me();
 * api.plugins.auth.logout();
 * ```
 *
 * @example API Key strategy
 * ```typescript
 * const api = createApiClient({ ... }, {
 *   baseUrl: 'https://api.example.com',
 *   plugins: [
 *     auth({ strategy: 'api-key', key: process.env.API_KEY! }),
 *   ] as const,
 * });
 * ```
 *
 * @example OAuth2 Client Credentials
 * ```typescript
 * const api = createApiClient({ ... }, {
 *   baseUrl: 'https://api.example.com',
 *   plugins: [
 *     auth({
 *       strategy: 'oauth2',
 *       grantType: 'client_credentials',
 *       clientId: process.env.CLIENT_ID!,
 *       clientSecret: process.env.CLIENT_SECRET!,
 *       tokenEndpoint: 'https://auth.example.com/oauth/token',
 *       scope: 'read write',
 *     }),
 *   ] as const,
 * });
 * ```
 *
 * @example HMAC signing
 * ```typescript
 * const api = createApiClient({ ... }, {
 *   baseUrl: 'https://api.example.com',
 *   plugins: [
 *     auth({
 *       strategy: 'hmac',
 *       secret: process.env.HMAC_SECRET!,
 *       header: 'X-Signature',
 *       includeBodyHash: true,
 *     }),
 *   ] as const,
 * });
 * ```
 *
 * @example Custom strategy
 * ```typescript
 * const api = createApiClient({ ... }, {
 *   baseUrl: 'https://api.example.com',
 *   plugins: [
 *     auth({
 *       strategy: 'custom',
 *       getHeaders: async ({ url }) => ({
 *         'X-Service-Token': await tokenService.get(url),
 *       }),
 *     }),
 *   ] as const,
 * });
 * ```
 */
// TypeScript distributes `TConfig extends void` over the discriminated union,
// turning the factory type into a union of narrow function types. Casting to
// `any` avoids that while keeping the public `Plugin<'auth', AuthPluginConfig,
// AuthPluginMethods>` type intact via the return type of `createPlugin`.
export const auth = createPlugin('auth', ((config: AuthPluginConfig) => {
  // -------------------------------------------------------------------------
  // Plugin-level state — shared across ALL endpoint requests
  // -------------------------------------------------------------------------

  const storage = resolveStorage(config);
  const tokenKey = (config as Record<string, unknown>)['tokenStorageKey'] as string | undefined ?? 'token';
  const refreshTokenKey = (config as Record<string, unknown>)['refreshTokenStorageKey'] as string | undefined ?? 'refreshToken';

  // Seed storage with tokens supplied directly in the config
  if (config.strategy === 'jwt') {
    if (config.token) storage.set(tokenKey, config.token);
    if (config.refreshToken) storage.set(refreshTokenKey, config.refreshToken);
  }
  // Build the strategy-specific fetch creator (closes over shared state)
  const strategyCreator = buildStrategyCreator(config, storage, tokenKey, refreshTokenKey);

  // -------------------------------------------------------------------------
  // Return plugin options
  // -------------------------------------------------------------------------

  return {
    handlerWrapper: <TInput, TOutput>(
      originalHandler: (
        input: TInput,
        context: HandlerContext,
      ) => Promise<TOutput>,
    ) => {
      return async (input: TInput, context: HandlerContext): Promise<TOutput> => {
        const authFetch = strategyCreator(context.fetch, context);
        return originalHandler(input, { ...context, fetch: authFetch });
      };
    },

    methods: {
      /**
       * Store an access token in the configured storage adapter.
       * Subsequent requests will use this token.
       *
       * @example
       * ```typescript
       * api.plugins.auth.setToken(await loginAndGetToken());
       * ```
       */
      setToken(token: string): void {
        storage.set(tokenKey, token);
      },

      /**
       * Retrieve the current access token, or `null` if none is stored.
       *
       * @example
       * ```typescript
       * const token = api.plugins.auth.getToken();
       * console.log('Current token:', token);
       * ```
       */
      getToken(): string | null {
        return storage.get(tokenKey);
      },

      /**
       * Store a refresh token in the configured storage adapter.
       *
       * @example
       * ```typescript
       * api.plugins.auth.setRefreshToken(refreshToken);
       * ```
       */
      setRefreshToken(token: string): void {
        storage.set(refreshTokenKey, token);
      },

      /**
       * Retrieve the current refresh token, or `null` if none is stored.
       *
       * @example
       * ```typescript
       * const rt = api.plugins.auth.getRefreshToken();
       * ```
       */
      getRefreshToken(): string | null {
        return storage.get(refreshTokenKey);
      },

      /**
       * Clear all tokens from the configured storage adapter.
       * After calling this, `isAuthenticated()` returns `false`.
       *
       * @example
       * ```typescript
       * api.plugins.auth.logout();
       * ```
       */
      logout(): void {
        storage.clear();
      },

      /**
       * Returns `true` if an access token is currently stored.
       *
       * @example
       * ```typescript
       * if (!api.plugins.auth.isAuthenticated()) {
       *   redirectToLogin();
       * }
       * ```
       */
      isAuthenticated(): boolean {
        return storage.get(tokenKey) !== null;
      },
    },
  };
}) as any);
