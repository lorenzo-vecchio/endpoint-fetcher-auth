import { describe, it, expect, vi } from 'vitest';
import { auth } from '../../src/plugin';
import { MemoryTokenStorage } from '../../src/storage/memory';

const makeContext = (fetchFn = vi.fn()) => ({
  fetch: fetchFn,
  method: 'GET',
  path: '/test',
  baseUrl: 'https://api.example.com',
});

describe('auth() plugin creation', () => {
  it('should create a plugin with name "auth"', () => {
    const plugin = auth({ strategy: 'bearer' });
    expect(plugin.name).toBe('auth');
  });

  it('should expose a handlerWrapper function', () => {
    const plugin = auth({ strategy: 'bearer' });
    expect(typeof plugin.handlerWrapper).toBe('function');
  });

  it('should expose all required methods', () => {
    const plugin = auth({ strategy: 'bearer' });
    expect(typeof plugin.methods!.setToken).toBe('function');
    expect(typeof plugin.methods!.getToken).toBe('function');
    expect(typeof plugin.methods!.setRefreshToken).toBe('function');
    expect(typeof plugin.methods!.getRefreshToken).toBe('function');
    expect(typeof plugin.methods!.logout).toBe('function');
    expect(typeof plugin.methods!.isAuthenticated).toBe('function');
  });
});

describe('auth() plugin methods', () => {
  it('setToken / getToken should store and retrieve an access token', () => {
    const plugin = auth({ strategy: 'bearer' });
    plugin.methods!.setToken('my-token');
    expect(plugin.methods!.getToken()).toBe('my-token');
  });

  it('setRefreshToken / getRefreshToken should store and retrieve a refresh token', () => {
    const plugin = auth({ strategy: 'jwt' });
    plugin.methods!.setRefreshToken('my-refresh');
    expect(plugin.methods!.getRefreshToken()).toBe('my-refresh');
  });

  it('isAuthenticated should return false before a token is set', () => {
    const plugin = auth({ strategy: 'bearer' });
    expect(plugin.methods!.isAuthenticated()).toBe(false);
  });

  it('isAuthenticated should return true after a token is set', () => {
    const plugin = auth({ strategy: 'bearer' });
    plugin.methods!.setToken('tok');
    expect(plugin.methods!.isAuthenticated()).toBe(true);
  });

  it('logout should clear all tokens', () => {
    const plugin = auth({ strategy: 'jwt' });
    plugin.methods!.setToken('access');
    plugin.methods!.setRefreshToken('refresh');
    plugin.methods!.logout();
    expect(plugin.methods!.getToken()).toBeNull();
    expect(plugin.methods!.getRefreshToken()).toBeNull();
    expect(plugin.methods!.isAuthenticated()).toBe(false);
  });

  it('should seed storage from jwt config token', () => {
    const plugin = auth({ strategy: 'jwt', token: 'seed-token', refreshToken: 'seed-refresh' });
    expect(plugin.methods!.getToken()).toBe('seed-token');
    expect(plugin.methods!.getRefreshToken()).toBe('seed-refresh');
  });

  it('should use a custom storage adapter', () => {
    const storage = new MemoryTokenStorage();
    const plugin = auth({ strategy: 'jwt', storage });
    plugin.methods!.setToken('via-custom-storage');
    expect(storage.get('token')).toBe('via-custom-storage');
  });

  it('should use custom storage keys', () => {
    const storage = new MemoryTokenStorage();
    const plugin = auth({
      strategy: 'jwt',
      storage,
      tokenStorageKey: 'my_token',
      refreshTokenStorageKey: 'my_refresh',
    });
    plugin.methods!.setToken('t');
    plugin.methods!.setRefreshToken('r');
    expect(storage.get('my_token')).toBe('t');
    expect(storage.get('my_refresh')).toBe('r');
  });
});

describe('auth() handlerWrapper', () => {
  it('should call the original handler', async () => {
    const plugin = auth({ strategy: 'api-key', key: 'k' });
    const originalHandler = vi.fn().mockResolvedValue({ data: 'ok' });
    const wrapped = plugin.handlerWrapper!(originalHandler, {} as any);

    const context = makeContext(vi.fn().mockResolvedValue({ ok: true, status: 200, headers: new Headers(), json: async () => ({}) }));
    await wrapped({}, context);

    expect(originalHandler).toHaveBeenCalledTimes(1);
  });

  it('should pass a modified fetch to the original handler', async () => {
    const plugin = auth({ strategy: 'api-key', key: 'test-key', in: 'header', name: 'X-API-Key' });
    const originalHandler = vi.fn().mockImplementation(async (_input, ctx) => {
      // Capture the fetch that was passed
      return { usedFetch: ctx.fetch };
    });
    const wrapped = plugin.handlerWrapper!(originalHandler, {} as any);

    const rawFetch = vi.fn();
    const context = { ...makeContext(rawFetch) };
    const result = await wrapped({}, context) as any;

    // The handler received a different (wrapped) fetch
    expect(result.usedFetch).not.toBe(rawFetch);
  });

  it('should propagate errors from the original handler', async () => {
    const plugin = auth({ strategy: 'bearer', token: 't' });
    const originalHandler = vi.fn().mockRejectedValue(new Error('handler error'));
    const wrapped = plugin.handlerWrapper!(originalHandler, {} as any);

    await expect(wrapped({}, makeContext())).rejects.toThrow('handler error');
  });
});
