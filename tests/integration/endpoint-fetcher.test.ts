import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createApiClient, get, post, group } from 'endpoint-fetcher';
import { auth } from '../../src/plugin';
import { MemoryTokenStorage } from '../../src/storage/memory';
import type { Mock } from 'vitest';

describe('Integration: auth plugin with endpoint-fetcher', () => {
  let mockFetch: Mock;

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  const ok = (data: unknown) => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers(),
    json: async () => data,
    text: async () => JSON.stringify(data),
  });

  const unauthorized = (wwwAuth?: string) => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    headers: new Headers(wwwAuth ? { 'WWW-Authenticate': wwwAuth } : {}),
    json: async () => ({ error: 'Unauthorized' }),
    text: async () => 'Unauthorized',
  });

  // -------------------------------------------------------------------------
  // Bearer strategy
  // -------------------------------------------------------------------------

  describe('strategy: bearer', () => {
    it('should attach Bearer token to requests', async () => {
      mockFetch.mockResolvedValue(ok({ id: 1 }));

      const api = createApiClient(
        { getMe: get<void, { id: number }>('/me') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer', token: 'my-bearer-token' })],
        },
      );

      await api.getMe();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('Authorization')).toBe('Bearer my-bearer-token');
    });

    it('should update token via setToken()', async () => {
      mockFetch.mockResolvedValue(ok({ id: 1 }));

      const api = createApiClient(
        { getMe: get<void, { id: number }>('/me') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer' })] as const,
        },
      );

      api.plugins.auth.setToken('updated-token');
      await api.getMe();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('Authorization')).toBe('Bearer updated-token');
    });

    it('isAuthenticated returns correct state', () => {
      const api = createApiClient(
        { getMe: get<void, { id: number }>('/me') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer' })] as const,
        },
      );

      expect(api.plugins.auth.isAuthenticated()).toBe(false);
      api.plugins.auth.setToken('tok');
      expect(api.plugins.auth.isAuthenticated()).toBe(true);
      api.plugins.auth.logout();
      expect(api.plugins.auth.isAuthenticated()).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // JWT strategy
  // -------------------------------------------------------------------------

  describe('strategy: jwt', () => {
    it('seeds the token from config and attaches it', async () => {
      mockFetch.mockResolvedValue(ok({ data: 'ok' }));

      const api = createApiClient(
        { getData: get<void, { data: string }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'jwt', token: 'seed-jwt' })],
        },
      );

      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('Authorization')).toBe('Bearer seed-jwt');
    });

    it('auto-refreshes on 401 and retries', async () => {
      mockFetch
        .mockResolvedValueOnce(unauthorized())
        .mockResolvedValueOnce(ok({ data: 'refreshed' }));

      const refreshCallback = vi.fn().mockResolvedValue({
        token: 'new-jwt',
        refreshToken: 'new-refresh',
      });

      const storage = new MemoryTokenStorage();
      storage.set('token', 'old-jwt');
      storage.set('refreshToken', 'old-refresh');

      const api = createApiClient(
        { getData: get<void, { data: string }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'jwt', storage, refreshCallback })],
        },
      );

      const result = await api.getData();

      expect(refreshCallback).toHaveBeenCalledWith('old-refresh');
      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ data: 'refreshed' });

      // Token and refresh token updated in storage
      expect(storage.get('token')).toBe('new-jwt');
      expect(storage.get('refreshToken')).toBe('new-refresh');
    });

    it('returns 401 error when refresh fails', async () => {
      mockFetch.mockResolvedValue(unauthorized());

      const api = createApiClient(
        { getData: get<void, { data: string }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'jwt', token: 'expired-jwt' })],
        },
      );

      // No refresh token => no retry, handler should throw or return error
      await expect(api.getData()).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // API Key strategy
  // -------------------------------------------------------------------------

  describe('strategy: api-key', () => {
    it('attaches key as X-API-Key header', async () => {
      mockFetch.mockResolvedValue(ok({ data: 'ok' }));

      const api = createApiClient(
        { getData: get<void, { data: string }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'api-key', key: 'sk-test' })],
        },
      );

      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('X-API-Key')).toBe('sk-test');
    });

    it('attaches key as query param when in=query', async () => {
      mockFetch.mockResolvedValue(ok({ data: 'ok' }));

      const api = createApiClient(
        { getData: get<void, { data: string }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'api-key', key: 'qk', in: 'query', name: 'api_key' })],
        },
      );

      await api.getData();

      const [calledUrl] = mockFetch.mock.calls[0];
      expect(String(calledUrl)).toContain('api_key=qk');
    });
  });

  // -------------------------------------------------------------------------
  // Basic Auth strategy
  // -------------------------------------------------------------------------

  describe('strategy: basic', () => {
    it('attaches Authorization: Basic header', async () => {
      mockFetch.mockResolvedValue(ok({ ok: true }));

      const api = createApiClient(
        { getData: get<void, { ok: boolean }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'basic', username: 'alice', password: 'pass' })],
        },
      );

      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      const authHeader = new Headers(init.headers).get('Authorization')!;
      expect(authHeader).toMatch(/^Basic /);
      expect(atob(authHeader.slice(6))).toBe('alice:pass');
    });
  });

  // -------------------------------------------------------------------------
  // HMAC strategy
  // -------------------------------------------------------------------------

  describe('strategy: hmac', () => {
    it('attaches X-Signature header on every request', async () => {
      mockFetch.mockResolvedValue(ok({ ok: true }));

      const api = createApiClient(
        { getData: get<void, { ok: boolean }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'hmac', secret: 'test-secret', includeTimestamp: false })],
        },
      );

      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      const sig = new Headers(init.headers).get('X-Signature');
      expect(sig).toBeTruthy();
      expect(sig).toMatch(/^[0-9a-f]+$/);
    });
  });

  // -------------------------------------------------------------------------
  // Custom strategy
  // -------------------------------------------------------------------------

  describe('strategy: custom', () => {
    it('attaches headers returned by getHeaders', async () => {
      mockFetch.mockResolvedValue(ok({ ok: true }));

      const api = createApiClient(
        { getData: get<void, { ok: boolean }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [
            auth({
              strategy: 'custom',
              getHeaders: () => ({ 'X-Tenant-Id': 'acme', 'X-Version': '2' }),
            }),
          ],
        },
      );

      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init.headers);
      expect(headers.get('X-Tenant-Id')).toBe('acme');
      expect(headers.get('X-Version')).toBe('2');
    });
  });

  // -------------------------------------------------------------------------
  // Plugin methods via client.plugins.auth
  // -------------------------------------------------------------------------

  describe('client.plugins.auth methods', () => {
    it('exposes setToken, getToken, setRefreshToken, getRefreshToken, logout, isAuthenticated', () => {
      const api = createApiClient(
        { getData: get<void, unknown>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer' })] as const,
        },
      );

      expect(typeof api.plugins.auth.setToken).toBe('function');
      expect(typeof api.plugins.auth.getToken).toBe('function');
      expect(typeof api.plugins.auth.setRefreshToken).toBe('function');
      expect(typeof api.plugins.auth.getRefreshToken).toBe('function');
      expect(typeof api.plugins.auth.logout).toBe('function');
      expect(typeof api.plugins.auth.isAuthenticated).toBe('function');
    });

    it('setToken affects subsequent requests', async () => {
      mockFetch.mockResolvedValue(ok({ ok: true }));

      const api = createApiClient(
        { getData: get<void, { ok: boolean }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer' })] as const,
        },
      );

      api.plugins.auth.setToken('dynamic-token');
      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('Authorization')).toBe('Bearer dynamic-token');
    });

    it('logout clears the token so subsequent requests send no auth header', async () => {
      mockFetch.mockResolvedValue(ok({ ok: true }));

      const api = createApiClient(
        { getData: get<void, { ok: boolean }>('/data') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer', token: 'tok' })] as const,
        },
      );

      api.plugins.auth.logout();
      await api.getData();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('Authorization')).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Grouped endpoints
  // -------------------------------------------------------------------------

  describe('works with grouped endpoints', () => {
    it('applies auth to requests inside groups', async () => {
      mockFetch.mockResolvedValue(ok([{ id: 1 }]));

      const api = createApiClient(
        {
          users: group({
            endpoints: {
              list: get<void, { id: number }[]>('/users'),
            },
          }),
        },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'api-key', key: 'group-key' })],
        },
      );

      await api.users.list();

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('X-API-Key')).toBe('group-key');
    });
  });

  // -------------------------------------------------------------------------
  // Multiple endpoints share the same storage
  // -------------------------------------------------------------------------

  describe('shared storage across endpoints', () => {
    it('token set via methods is used by all endpoints', async () => {
      mockFetch.mockResolvedValue(ok({ ok: true }));

      const api = createApiClient(
        {
          ep1: get<void, { ok: boolean }>('/ep1'),
          ep2: get<void, { ok: boolean }>('/ep2'),
        },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'bearer' })] as const,
        },
      );

      api.plugins.auth.setToken('shared-token');

      await api.ep1();
      await api.ep2();

      for (const call of mockFetch.mock.calls) {
        const headers = new Headers(call[1].headers);
        expect(headers.get('Authorization')).toBe('Bearer shared-token');
      }
    });
  });

  // -------------------------------------------------------------------------
  // POST endpoints
  // -------------------------------------------------------------------------

  describe('applies auth to POST endpoints', () => {
    it('attaches the api-key header to POST requests', async () => {
      mockFetch.mockResolvedValue(ok({ id: 42 }));

      const api = createApiClient(
        { createUser: post<{ name: string }, { id: number }>('/users') },
        {
          baseUrl: 'https://api.example.com',
          fetch: mockFetch,
          plugins: [auth({ strategy: 'api-key', key: 'post-key' })],
        },
      );

      await api.createUser({ name: 'Alice' });

      const [, init] = mockFetch.mock.calls[0];
      expect(new Headers(init.headers).get('X-API-Key')).toBe('post-key');
    });
  });
});
