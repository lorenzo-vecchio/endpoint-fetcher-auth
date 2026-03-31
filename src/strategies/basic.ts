import type { BasicAuthConfig, HandlerContext } from '../types';

/**
 * Creates a fetch wrapper that implements HTTP Basic authentication (RFC 7617).
 *
 * Encodes `username:password` in Base64 and attaches it as
 * `Authorization: Basic <credentials>` on every request.
 *
 * @param config - Basic auth strategy configuration.
 * @returns A function that wraps a `fetch` instance with Basic auth logic.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * // Static credentials
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({ strategy: 'basic', username: 'alice', password: 's3cr3t' }),
 *   ] as const,
 * });
 *
 * // Dynamic credentials
 * const api2 = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'basic',
 *       getCredentials: async () => ({
 *         username: await vault.getUsername(),
 *         password: await vault.getPassword(),
 *       }),
 *     }),
 *   ] as const,
 * });
 * ```
 */
export function createBasicFetch(
  config: BasicAuthConfig,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  return (originalFetch: typeof fetch, _context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      let username: string;
      let password: string;

      if (config.getCredentials) {
        const creds = await config.getCredentials();
        username = creds.username;
        password = creds.password;
      } else {
        username = config.username ?? '';
        password = config.password ?? '';
      }

      const encoded = btoa(`${username}:${password}`);
      const headers = new Headers(init?.headers);
      headers.set('Authorization', `Basic ${encoded}`);

      return originalFetch(input, { ...init, headers });
    };
  };
}
