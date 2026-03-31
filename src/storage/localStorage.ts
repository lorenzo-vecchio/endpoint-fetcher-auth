import type { TokenStorage } from '../types';

/**
 * Options for `LocalStorageTokenStorage`.
 */
export interface LocalStorageTokenStorageOptions {
  /**
   * String prepended to every key before writing to `localStorage`.
   * @default 'ef_auth_'
   */
  prefix?: string;
}

/**
 * Browser `localStorage`-backed token storage.
 *
 * All tokens survive page reloads but are cleared when the user clears
 * browser storage. Not available in Node.js environments (use
 * `MemoryTokenStorage` or `CookieTokenStorage` instead).
 *
 * @example
 * ```typescript
 * import { auth, LocalStorageTokenStorage } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'jwt',
 *       storage: new LocalStorageTokenStorage({ prefix: 'myapp_' }),
 *     }),
 *   ],
 * });
 * ```
 */
export class LocalStorageTokenStorage implements TokenStorage {
  private readonly prefix: string;

  constructor(options: LocalStorageTokenStorageOptions = {}) {
    this.prefix = options.prefix ?? 'ef_auth_';
  }

  private key(k: string): string {
    return `${this.prefix}${k}`;
  }

  /** @inheritdoc */
  get(key: string): string | null {
    return localStorage.getItem(this.key(key));
  }

  /** @inheritdoc */
  set(key: string, value: string): void {
    localStorage.setItem(this.key(key), value);
  }

  /** @inheritdoc */
  delete(key: string): void {
    localStorage.removeItem(this.key(key));
  }

  /**
   * Removes all keys that start with this instance's prefix.
   * Other `localStorage` entries are left untouched.
   */
  clear(): void {
    const toRemove = Object.keys(localStorage).filter(k => k.startsWith(this.prefix));
    toRemove.forEach(k => localStorage.removeItem(k));
  }
}
