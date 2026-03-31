import type { CustomAuthConfig, HandlerContext } from '../types';

/**
 * Creates a fetch wrapper that implements a fully custom authentication strategy.
 *
 * Calls `getHeaders(context)` before every request and merges the returned
 * headers into the request. This gives you complete control over the
 * authentication flow.
 *
 * @param config  - Custom auth strategy configuration.
 * @returns A function that wraps a `fetch` instance with custom auth headers.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'custom',
 *       getHeaders: async ({ method, path, url }) => ({
 *         'X-Request-Id': crypto.randomUUID(),
 *         'X-Service-Token': await myTokenService.getToken(),
 *         'X-Method': method,
 *       }),
 *     }),
 *   ] as const,
 * });
 * ```
 */
export function createCustomFetch(
  config: CustomAuthConfig,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  return (originalFetch: typeof fetch, context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      const rawUrl = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? context.method ?? 'GET';

      const extraHeaders = await config.getHeaders({
        method: method.toUpperCase(),
        path: context.path,
        baseUrl: context.baseUrl,
        url: rawUrl,
      });

      const headers = new Headers(init?.headers);
      for (const [key, value] of Object.entries(extraHeaders)) {
        headers.set(key, value);
      }

      return originalFetch(input, { ...init, headers });
    };
  };
}
