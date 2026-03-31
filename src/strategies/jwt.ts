import type { JwtAuthConfig, TokenStorage, HandlerContext } from '../types';

/**
 * Creates a fetch wrapper that implements JWT Bearer authentication.
 *
 * - Reads the current access token from `storage` and attaches it as
 *   `Authorization: Bearer <token>` on every request.
 * - When `autoRefresh` is `true` (default) and the server responds with 401,
 *   attempts to refresh the token via `refreshCallback` or `refreshEndpoint`,
 *   stores the new token, and retries the original request once.
 *
 * @param config   JWT strategy configuration.
 * @param storage  Token storage adapter.
 * @param tokenKey Storage key for the access token.
 * @param refreshTokenKey Storage key for the refresh token.
 * @returns A function that wraps a `fetch` instance with JWT auth logic.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'jwt',
 *       token: 'initial-access-token',
 *       refreshCallback: async (rt) => {
 *         const res = await fetch('/auth/refresh', {
 *           method: 'POST',
 *           body: JSON.stringify({ refresh_token: rt }),
 *         });
 *         const data = await res.json();
 *         return { token: data.access_token, refreshToken: data.refresh_token };
 *       },
 *     }),
 *   ] as const,
 * });
 * ```
 */
export function createJwtFetch(
  config: JwtAuthConfig,
  storage: TokenStorage,
  tokenKey: string,
  refreshTokenKey: string,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  const autoRefresh = config.autoRefresh ?? true;

  return (originalFetch: typeof fetch, _context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      const token = storage.get(tokenKey);
      const headers = new Headers(init?.headers);
      if (token) headers.set('Authorization', `Bearer ${token}`);

      const response = await originalFetch(input, { ...init, headers });

      if (response.status !== 401 || !autoRefresh) {
        return response;
      }

      // Attempt token refresh
      const refreshToken = storage.get(refreshTokenKey);
      let newToken: string | null = null;
      let newRefreshToken: string | null = null;

      if (config.refreshCallback && refreshToken) {
        try {
          const result = await config.refreshCallback(refreshToken);
          newToken = result.token;
          newRefreshToken = result.refreshToken ?? null;
        } catch {
          // Refresh failed — return the original 401 response
        }
      } else if (config.refreshEndpoint && refreshToken) {
        try {
          const refreshResp = await originalFetch(config.refreshEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken }),
          });
          if (refreshResp.ok) {
            const data = await refreshResp.json();
            newToken = data.access_token ?? data.token ?? null;
            newRefreshToken = data.refresh_token ?? null;
          }
        } catch {
          // Refresh request failed — return the original 401 response
        }
      }

      if (!newToken) return response;

      storage.set(tokenKey, newToken);
      if (newRefreshToken) storage.set(refreshTokenKey, newRefreshToken);

      // Retry with the new token
      const retryHeaders = new Headers(init?.headers);
      retryHeaders.set('Authorization', `Bearer ${newToken}`);
      return originalFetch(input, { ...init, headers: retryHeaders });
    };
  };
}
