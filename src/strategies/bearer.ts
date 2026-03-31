import type { BearerAuthConfig, TokenStorage, HandlerContext } from '../types';

/**
 * Creates a fetch wrapper that implements the generic Bearer token strategy.
 *
 * Attaches `Authorization: Bearer <token>` on every request. The token is
 * resolved in the following priority order:
 * 1. `getToken()` callback (if provided)
 * 2. `token` static value (if provided in config)
 * 3. Value in `storage` under `tokenKey`
 *
 * @param config    Bearer strategy configuration.
 * @param storage   Token storage adapter.
 * @param tokenKey  Storage key for the bearer token.
 * @returns A function that wraps a `fetch` instance with Bearer auth logic.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * // Static token
 * const api = createApiClient({ ... }, {
 *   plugins: [auth({ strategy: 'bearer', token: 'my-opaque-token' })] as const,
 * });
 *
 * // Dynamic token
 * const api2 = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'bearer',
 *       getToken: async () => secretsManager.getCurrentToken(),
 *     }),
 *   ] as const,
 * });
 *
 * // Via plugin methods
 * const api3 = createApiClient({ ... }, {
 *   plugins: [auth({ strategy: 'bearer' })] as const,
 * });
 * api3.plugins.auth.setToken('new-token');
 * ```
 */
export function createBearerFetch(
  config: BearerAuthConfig,
  storage: TokenStorage,
  tokenKey: string,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  // Seed storage from the static token so that logout() clears it correctly
  if (!config.getToken && config.token) {
    storage.set(tokenKey, config.token);
  }

  return (originalFetch: typeof fetch, _context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      let token: string | null = null;

      if (config.getToken) {
        // Dynamic token always takes priority
        token = await config.getToken();
      } else {
        // Static config.token is seeded into storage at plugin creation;
        // always read from storage so that logout() can clear it.
        token = storage.get(tokenKey);
      }

      const headers = new Headers(init?.headers);
      if (token) headers.set('Authorization', `Bearer ${token}`);

      return originalFetch(input, { ...init, headers });
    };
  };
}
