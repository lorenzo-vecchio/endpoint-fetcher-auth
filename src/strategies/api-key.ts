import type { ApiKeyAuthConfig, HandlerContext } from '../types';

/**
 * Creates a fetch wrapper that implements the API Key authentication strategy.
 *
 * Attaches the API key either as a request header (default `X-API-Key`) or as
 * a URL query parameter (default `api_key`), depending on the `in` option.
 *
 * @param config - API key strategy configuration.
 * @returns A function that wraps a `fetch` instance with API key auth logic.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * // Attach via header (default)
 * const api = createApiClient({ ... }, {
 *   plugins: [auth({ strategy: 'api-key', key: 'sk-abc123' })] as const,
 * });
 *
 * // Attach via query parameter
 * const api2 = createApiClient({ ... }, {
 *   plugins: [
 *     auth({ strategy: 'api-key', key: 'sk-abc123', in: 'query', name: 'token' }),
 *   ] as const,
 * });
 * ```
 */
export function createApiKeyFetch(
  config: ApiKeyAuthConfig,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  const location = config.in ?? 'header';
  const keyName = config.name ?? (location === 'header' ? 'X-API-Key' : 'api_key');

  return (originalFetch: typeof fetch, _context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      if (location === 'header') {
        const headers = new Headers(init?.headers);
        headers.set(keyName, config.key);
        return originalFetch(input, { ...init, headers });
      }

      // Query parameter
      const rawUrl = input instanceof Request ? input.url : String(input);
      const url = new URL(rawUrl);
      url.searchParams.set(keyName, config.key);

      if (input instanceof Request) {
        const newRequest = new Request(url.toString(), input);
        return originalFetch(newRequest, init);
      }

      return originalFetch(url.toString(), init);
    };
  };
}
