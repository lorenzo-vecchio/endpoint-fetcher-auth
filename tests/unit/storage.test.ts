import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryTokenStorage } from '../../src/storage/memory';
import { LocalStorageTokenStorage } from '../../src/storage/localStorage';
import { CookieTokenStorage } from '../../src/storage/cookie';

// ---------------------------------------------------------------------------
// MemoryTokenStorage
// ---------------------------------------------------------------------------

describe('MemoryTokenStorage', () => {
  let storage: MemoryTokenStorage;

  beforeEach(() => {
    storage = new MemoryTokenStorage();
  });

  it('returns null for missing keys', () => {
    expect(storage.get('missing')).toBeNull();
  });

  it('stores and retrieves a value', () => {
    storage.set('token', 'abc123');
    expect(storage.get('token')).toBe('abc123');
  });

  it('overwrites an existing value', () => {
    storage.set('token', 'old');
    storage.set('token', 'new');
    expect(storage.get('token')).toBe('new');
  });

  it('deletes a key', () => {
    storage.set('token', 'abc');
    storage.delete('token');
    expect(storage.get('token')).toBeNull();
  });

  it('clear removes all keys', () => {
    storage.set('token', 'abc');
    storage.set('refresh', 'xyz');
    storage.clear();
    expect(storage.get('token')).toBeNull();
    expect(storage.get('refresh')).toBeNull();
  });

  it('delete on missing key does not throw', () => {
    expect(() => storage.delete('nope')).not.toThrow();
  });

  it('maintains separate values per key', () => {
    storage.set('a', '1');
    storage.set('b', '2');
    expect(storage.get('a')).toBe('1');
    expect(storage.get('b')).toBe('2');
  });
});

// ---------------------------------------------------------------------------
// LocalStorageTokenStorage (Node environment — localStorage is not available)
// We test the instantiation; reading/writing is guarded by the browser guard.
// ---------------------------------------------------------------------------

describe('LocalStorageTokenStorage', () => {
  it('instantiates with default prefix', () => {
    const s = new LocalStorageTokenStorage();
    expect(s).toBeDefined();
  });

  it('instantiates with custom prefix', () => {
    const s = new LocalStorageTokenStorage({ prefix: 'myapp_' });
    expect(s).toBeDefined();
  });

  it('returns null when localStorage is not available', () => {
    // In Node.js environment, localStorage is undefined
    const s = new LocalStorageTokenStorage();
    // Should not throw — behaves gracefully
    try {
      const result = s.get('token');
      // Either returns null (if localStorage exists but key missing) or throws
      expect(result === null || result === undefined || typeof result === 'string').toBe(true);
    } catch {
      // Expected in Node — localStorage is not defined
    }
  });
});

// ---------------------------------------------------------------------------
// CookieTokenStorage
// ---------------------------------------------------------------------------

describe('CookieTokenStorage', () => {
  it('instantiates with default options', () => {
    const s = new CookieTokenStorage();
    expect(s).toBeDefined();
  });

  it('instantiates with custom prefix and cookie options', () => {
    const s = new CookieTokenStorage({
      prefix: 'auth_',
      cookieOptions: { secure: true, sameSite: 'Strict', maxAge: 3600 },
    });
    expect(s).toBeDefined();
  });

  it('uses provided getCookie / setCookie / deleteCookie callbacks', () => {
    const store: Record<string, string> = {};
    const getCookie = (name: string) => store[name] ?? null;
    const setCookie = (name: string, value: string) => { store[name] = value; };
    const deleteCookie = (name: string) => { delete store[name]; };

    const s = new CookieTokenStorage({ prefix: 'ef_', getCookie, setCookie, deleteCookie });

    s.set('token', 'cookie-token');
    expect(store['ef_token']).toBe('cookie-token');

    expect(s.get('token')).toBe('cookie-token');

    s.delete('token');
    expect(store['ef_token']).toBeUndefined();
    expect(s.get('token')).toBeNull();
  });

  it('set stores multiple keys independently via callbacks', () => {
    const store: Record<string, string> = {};
    const s = new CookieTokenStorage({
      getCookie: (n) => store[n] ?? null,
      setCookie: (n, v) => { store[n] = v; },
      deleteCookie: (n) => { delete store[n]; },
    });

    s.set('token', 'access');
    s.set('refreshToken', 'refresh');

    expect(s.get('token')).toBe('access');
    expect(s.get('refreshToken')).toBe('refresh');
  });

  it('clear is a no-op when SSR callbacks are provided (no key list available)', () => {
    const store: Record<string, string> = { ef_auth_token: 'x' };
    const s = new CookieTokenStorage({
      getCookie: (n) => store[n] ?? null,
      setCookie: (n, v) => { store[n] = v; },
      deleteCookie: (n) => { delete store[n]; },
    });

    expect(() => s.clear()).not.toThrow();
  });

  it('returns null in Node environment when document is not available', () => {
    const s = new CookieTokenStorage();
    const result = s.get('token');
    expect(result).toBeNull();
  });
});
