import type { TokenStorage } from '../types';

/**
 * Cookie attributes that can be set when writing a token cookie.
 */
export interface CookieOptions {
  /** Cookie path. @default '/' */
  path?: string;
  /** Cookie domain. */
  domain?: string;
  /** Max age in seconds (takes precedence over `expires`). */
  maxAge?: number;
  /** Whether the cookie is only sent over HTTPS. */
  secure?: boolean;
  /**
   * Prevent client-side JavaScript access to the cookie.
   * Note: browser-side `document.cookie` cannot set HttpOnly cookies;
   * use the SSR callbacks to set this attribute server-side.
   */
  httpOnly?: boolean;
  /** SameSite policy. */
  sameSite?: 'Strict' | 'Lax' | 'None';
}

/**
 * Optional SSR callbacks that let you plug in any cookie library
 * (e.g. `js-cookie`, `cookie-universal`, Next.js `cookies()`).
 *
 * When these are not provided, `CookieTokenStorage` reads/writes
 * `document.cookie` directly (browser only).
 *
 * @example
 * ```typescript
 * // Next.js App Router (server component / route handler)
 * import { cookies } from 'next/headers';
 *
 * new CookieTokenStorage({
 *   getCookie: (name) => cookies().get(name)?.value ?? null,
 *   setCookie: (name, value, opts) => cookies().set(name, value, opts),
 *   deleteCookie: (name) => cookies().delete(name),
 * })
 * ```
 */
export interface CookieCallbacks {
  getCookie?: (name: string) => string | null;
  setCookie?: (name: string, value: string, options: CookieOptions) => void;
  deleteCookie?: (name: string, options?: Pick<CookieOptions, 'path' | 'domain'>) => void;
}

/**
 * Options for `CookieTokenStorage`.
 */
export interface CookieTokenStorageOptions extends CookieCallbacks {
  /**
   * String prepended to every cookie name.
   * @default 'ef_auth_'
   */
  prefix?: string;
  /** Default cookie attributes applied to every `set` call. */
  cookieOptions?: CookieOptions;
}

/**
 * Cookie-backed token storage — works in both browser and SSR environments.
 *
 * In the browser it reads/writes `document.cookie` directly.
 * For SSR (Node.js), pass `getCookie`/`setCookie`/`deleteCookie` callbacks
 * to delegate to your cookie library of choice.
 *
 * @example
 * ```typescript
 * // Browser usage
 * import { auth, CookieTokenStorage } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'jwt',
 *       storage: new CookieTokenStorage({
 *         prefix: 'myapp_',
 *         cookieOptions: { secure: true, sameSite: 'Strict', maxAge: 3600 },
 *       }),
 *     }),
 *   ],
 * });
 * ```
 */
export class CookieTokenStorage implements TokenStorage {
  private readonly prefix: string;
  private readonly cookieOptions: CookieOptions;
  private readonly getCookieFn?: (name: string) => string | null;
  private readonly setCookieFn?: (name: string, value: string, options: CookieOptions) => void;
  private readonly deleteCookieFn?: (name: string, options?: Pick<CookieOptions, 'path' | 'domain'>) => void;

  constructor(options: CookieTokenStorageOptions = {}) {
    this.prefix = options.prefix ?? 'ef_auth_';
    this.cookieOptions = { path: '/', ...options.cookieOptions };
    this.getCookieFn = options.getCookie;
    this.setCookieFn = options.setCookie;
    this.deleteCookieFn = options.deleteCookie;
  }

  private cookieName(key: string): string {
    return `${this.prefix}${key}`;
  }

  /** @inheritdoc */
  get(key: string): string | null {
    const name = this.cookieName(key);

    if (this.getCookieFn) {
      return this.getCookieFn(name);
    }

    // Browser fallback: parse document.cookie
    if (typeof document === 'undefined') return null;
    const match = document.cookie
      .split('; ')
      .find(row => row.startsWith(`${name}=`));
    return match ? decodeURIComponent(match.split('=').slice(1).join('=')) : null;
  }

  /** @inheritdoc */
  set(key: string, value: string): void {
    const name = this.cookieName(key);

    if (this.setCookieFn) {
      this.setCookieFn(name, value, this.cookieOptions);
      return;
    }

    // Browser fallback
    if (typeof document === 'undefined') return;
    let cookie = `${name}=${encodeURIComponent(value)}`;
    if (this.cookieOptions.path) cookie += `; Path=${this.cookieOptions.path}`;
    if (this.cookieOptions.domain) cookie += `; Domain=${this.cookieOptions.domain}`;
    if (this.cookieOptions.maxAge !== undefined) cookie += `; Max-Age=${this.cookieOptions.maxAge}`;
    if (this.cookieOptions.secure) cookie += '; Secure';
    if (this.cookieOptions.sameSite) cookie += `; SameSite=${this.cookieOptions.sameSite}`;
    document.cookie = cookie;
  }

  /** @inheritdoc */
  delete(key: string): void {
    const name = this.cookieName(key);

    if (this.deleteCookieFn) {
      this.deleteCookieFn(name, { path: this.cookieOptions.path, domain: this.cookieOptions.domain });
      return;
    }

    // Browser fallback: expire the cookie
    if (typeof document === 'undefined') return;
    let cookie = `${name}=; Max-Age=0`;
    if (this.cookieOptions.path) cookie += `; Path=${this.cookieOptions.path}`;
    if (this.cookieOptions.domain) cookie += `; Domain=${this.cookieOptions.domain}`;
    document.cookie = cookie;
  }

  /**
   * Deletes all cookies whose name starts with this instance's prefix.
   * Browser fallback only — for SSR, each key must be deleted individually.
   */
  clear(): void {
    if (this.deleteCookieFn) {
      // SSR: we don't know all keys, so callers should delete keys explicitly
      // or implement a custom clear via deleteCookieFn
      return;
    }

    if (typeof document === 'undefined') return;
    const cookiesToClear = document.cookie
      .split('; ')
      .map(row => row.split('=')[0])
      .filter(name => name.startsWith(this.prefix));

    cookiesToClear.forEach(name => {
      let cookie = `${name}=; Max-Age=0`;
      if (this.cookieOptions.path) cookie += `; Path=${this.cookieOptions.path}`;
      if (this.cookieOptions.domain) cookie += `; Domain=${this.cookieOptions.domain}`;
      document.cookie = cookie;
    });
  }
}
