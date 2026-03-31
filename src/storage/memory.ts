import type { TokenStorage } from '../types';

/**
 * In-memory token storage backed by a `Map`.
 *
 * This is the default storage adapter. All tokens are lost when the page
 * reloads or the Node.js process exits. Use `LocalStorageTokenStorage` or
 * `CookieTokenStorage` for persistent storage.
 *
 * @example
 * ```typescript
 * import { auth, MemoryTokenStorage } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'jwt',
 *       storage: new MemoryTokenStorage(),
 *     }),
 *   ],
 * });
 * ```
 */
export class MemoryTokenStorage implements TokenStorage {
  private readonly store = new Map<string, string>();

  /** @inheritdoc */
  get(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  /** @inheritdoc */
  set(key: string, value: string): void {
    this.store.set(key, value);
  }

  /** @inheritdoc */
  delete(key: string): void {
    this.store.delete(key);
  }

  /** @inheritdoc */
  clear(): void {
    this.store.clear();
  }
}
