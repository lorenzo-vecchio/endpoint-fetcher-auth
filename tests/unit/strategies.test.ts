import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryTokenStorage } from '../../src/storage/memory';
import { createJwtFetch } from '../../src/strategies/jwt';
import { createApiKeyFetch } from '../../src/strategies/api-key';
import { createBasicFetch } from '../../src/strategies/basic';
import { createBearerFetch } from '../../src/strategies/bearer';
import { createHmacFetch } from '../../src/strategies/hmac';
import { createDigestFetch, md5 } from '../../src/strategies/digest';
import { createCustomFetch } from '../../src/strategies/custom';

const fakeContext = (fetchFn?: typeof fetch) => ({
  fetch: fetchFn ?? vi.fn(),
  method: 'GET',
  path: '/test',
  baseUrl: 'https://api.example.com',
});

const ok200 = () => ({
  ok: true,
  status: 200,
  headers: new Headers(),
  json: async () => ({}),
  text: async () => '',
});

// ---------------------------------------------------------------------------
// md5 utility
// ---------------------------------------------------------------------------

describe('md5()', () => {
  it('produces the RFC-1321 test vector for empty string', () => {
    expect(md5('')).toBe('d41d8cd98f00b204e9800998ecf8427e');
  });

  it('produces the well-known digest for "abc"', () => {
    expect(md5('abc')).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  it('produces the well-known digest for "The quick brown fox..."', () => {
    expect(md5('The quick brown fox jumps over the lazy dog')).toBe(
      '9e107d9d372bb6826bd81d3542a419d6',
    );
  });
});

// ---------------------------------------------------------------------------
// JWT strategy
// ---------------------------------------------------------------------------

describe('createJwtFetch()', () => {
  let storage: MemoryTokenStorage;

  beforeEach(() => {
    storage = new MemoryTokenStorage();
  });

  it('attaches Authorization: Bearer header when token is present', async () => {
    storage.set('token', 'my-jwt');
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const fetchCreator = createJwtFetch({ strategy: 'jwt' }, storage, 'token', 'refreshToken');
    const authFetch = fetchCreator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/me', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer my-jwt');
  });

  it('does not set Authorization header when no token is stored', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const fetchCreator = createJwtFetch({ strategy: 'jwt' }, storage, 'token', 'refreshToken');
    const authFetch = fetchCreator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/me', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('Authorization')).toBeNull();
  });

  it('auto-refreshes token on 401 using refreshCallback', async () => {
    storage.set('token', 'expired-token');
    storage.set('refreshToken', 'my-refresh');

    const mockFetch = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 401, headers: new Headers(), json: async () => ({}) })
      .mockResolvedValueOnce(ok200());

    const refreshCallback = vi.fn().mockResolvedValue({ token: 'new-token', refreshToken: 'new-refresh' });

    const fetchCreator = createJwtFetch(
      { strategy: 'jwt', refreshCallback },
      storage, 'token', 'refreshToken',
    );
    const authFetch = fetchCreator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/me', {});

    expect(refreshCallback).toHaveBeenCalledWith('my-refresh');
    expect(storage.get('token')).toBe('new-token');
    expect(storage.get('refreshToken')).toBe('new-refresh');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('returns the 401 response when no refresh token is available', async () => {
    storage.set('token', 'expired');
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 401, headers: new Headers(), json: async () => ({}) });

    const fetchCreator = createJwtFetch({ strategy: 'jwt' }, storage, 'token', 'refreshToken');
    const authFetch = fetchCreator(mockFetch, fakeContext());

    const response = await authFetch('https://api.example.com/me', {});
    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('skips auto-refresh when autoRefresh is false', async () => {
    storage.set('token', 'expired');
    storage.set('refreshToken', 'rt');
    const refreshCallback = vi.fn().mockResolvedValue({ token: 'new' });
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 401, headers: new Headers(), json: async () => ({}) });

    const fetchCreator = createJwtFetch(
      { strategy: 'jwt', autoRefresh: false, refreshCallback },
      storage, 'token', 'refreshToken',
    );
    const authFetch = fetchCreator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/me', {});
    expect(refreshCallback).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// API Key strategy
// ---------------------------------------------------------------------------

describe('createApiKeyFetch()', () => {
  it('attaches the key as X-API-Key header by default', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createApiKeyFetch({ strategy: 'api-key', key: 'sk-123' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('X-API-Key')).toBe('sk-123');
  });

  it('uses a custom header name', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createApiKeyFetch({ strategy: 'api-key', key: 'tok', in: 'header', name: 'X-Token' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('X-Token')).toBe('tok');
    expect(headers.get('X-API-Key')).toBeNull();
  });

  it('attaches key as query parameter when in=query', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createApiKeyFetch({ strategy: 'api-key', key: 'qk', in: 'query', name: 'token' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain('token=qk');
  });

  it('uses api_key as default query param name', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createApiKeyFetch({ strategy: 'api-key', key: 'k2', in: 'query' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain('api_key=k2');
  });
});

// ---------------------------------------------------------------------------
// Basic Auth strategy
// ---------------------------------------------------------------------------

describe('createBasicFetch()', () => {
  it('encodes credentials and attaches Authorization: Basic header', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createBasicFetch({ strategy: 'basic', username: 'alice', password: 'pass' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    const auth = headers.get('Authorization')!;
    expect(auth).toMatch(/^Basic /);
    const decoded = atob(auth.slice('Basic '.length));
    expect(decoded).toBe('alice:pass');
  });

  it('uses getCredentials callback when provided', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const getCredentials = vi.fn().mockResolvedValue({ username: 'bob', password: 'secret' });
    const creator = createBasicFetch({ strategy: 'basic', getCredentials });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    expect(getCredentials).toHaveBeenCalledTimes(1);
    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    const decoded = atob(headers.get('Authorization')!.slice('Basic '.length));
    expect(decoded).toBe('bob:secret');
  });

  it('uses empty strings when no credentials are provided', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createBasicFetch({ strategy: 'basic' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    const decoded = atob(headers.get('Authorization')!.slice('Basic '.length));
    expect(decoded).toBe(':');
  });
});

// ---------------------------------------------------------------------------
// Bearer strategy
// ---------------------------------------------------------------------------

describe('createBearerFetch()', () => {
  let storage: MemoryTokenStorage;

  beforeEach(() => {
    storage = new MemoryTokenStorage();
  });

  it('attaches static token from config', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createBearerFetch({ strategy: 'bearer', token: 'static-tok' }, storage, 'token');
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer static-tok');
  });

  it('uses getToken callback when provided', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const getToken = vi.fn().mockResolvedValue('dynamic-tok');
    const creator = createBearerFetch({ strategy: 'bearer', getToken }, storage, 'token');
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    expect(getToken).toHaveBeenCalledTimes(1);
    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer dynamic-tok');
  });

  it('reads token from storage when no static token or callback', async () => {
    storage.set('token', 'storage-tok');
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createBearerFetch({ strategy: 'bearer' }, storage, 'token');
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer storage-tok');
  });

  it('does not set Authorization header when no token is available', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createBearerFetch({ strategy: 'bearer' }, storage, 'token');
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('Authorization')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// HMAC strategy
// ---------------------------------------------------------------------------

describe('createHmacFetch()', () => {
  it('attaches X-Signature header', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createHmacFetch({
      strategy: 'hmac',
      secret: 'test-secret',
      includeTimestamp: false,
    });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', { method: 'GET' });

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('X-Signature')).toBeTruthy();
    expect(headers.get('X-Signature')).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hex
  });

  it('uses custom header name', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createHmacFetch({
      strategy: 'hmac',
      secret: 'sec',
      header: 'X-My-Sig',
      includeTimestamp: false,
    });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', { method: 'GET' });

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.has('X-My-Sig')).toBe(true);
    expect(headers.has('X-Signature')).toBe(false);
  });

  it('includes X-Timestamp header when includeTimestamp is true (default)', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createHmacFetch({ strategy: 'hmac', secret: 'sec' });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', { method: 'GET' });

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    const ts = headers.get('X-Timestamp');
    expect(ts).toBeTruthy();
    expect(Number(ts)).toBeGreaterThan(0);
  });

  it('produces different signatures for different methods', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createHmacFetch({
      strategy: 'hmac',
      secret: 'sec',
      includeTimestamp: false,
    });

    const getFetch = creator(mockFetch, { ...fakeContext(), method: 'GET' });
    const postFetch = creator(mockFetch, { ...fakeContext(), method: 'POST' });

    await getFetch('https://api.example.com/data', { method: 'GET' });
    await postFetch('https://api.example.com/data', { method: 'POST' });

    const getSig = (mockFetch.mock.calls[0][1].headers as Headers).get('X-Signature');
    const postSig = (mockFetch.mock.calls[1][1].headers as Headers).get('X-Signature');
    expect(getSig).not.toBe(postSig);
  });
});

// ---------------------------------------------------------------------------
// Digest strategy
// ---------------------------------------------------------------------------

describe('createDigestFetch()', () => {
  it('passes through non-401 responses unchanged', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createDigestFetch({ strategy: 'digest', username: 'u', password: 'p' });
    const authFetch = creator(mockFetch, fakeContext());

    const response = await authFetch('https://api.example.com/data', {});
    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('passes through 401 without WWW-Authenticate: Digest header', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false, status: 401,
      headers: new Headers({ 'WWW-Authenticate': 'Bearer' }),
      json: async () => ({}),
    });
    const creator = createDigestFetch({ strategy: 'digest', username: 'u', password: 'p' });
    const authFetch = creator(mockFetch, fakeContext());

    const response = await authFetch('https://api.example.com/data', {});
    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('retries with Authorization: Digest header on 401 challenge', async () => {
    const challenge = 'Digest realm="example.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5, qop="auth"';
    const mockFetch = vi.fn()
      .mockResolvedValueOnce({
        ok: false, status: 401,
        headers: new Headers({ 'WWW-Authenticate': challenge }),
        json: async () => ({}),
      })
      .mockResolvedValueOnce(ok200());

    const creator = createDigestFetch({ strategy: 'digest', username: 'Mufasa', password: 'Circle Of Life' });
    const authFetch = creator(mockFetch, fakeContext());

    const response = await authFetch('https://api.example.com/data', { method: 'GET' });

    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(response.status).toBe(200);

    const retryHeaders = mockFetch.mock.calls[1][1].headers as Headers;
    const authHeader = retryHeaders.get('Authorization')!;
    expect(authHeader).toMatch(/^Digest /);
    expect(authHeader).toContain('username="Mufasa"');
    expect(authHeader).toContain('realm="example.com"');
  });
});

// ---------------------------------------------------------------------------
// Custom strategy
// ---------------------------------------------------------------------------

describe('createCustomFetch()', () => {
  it('attaches headers returned by getHeaders', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const getHeaders = vi.fn().mockResolvedValue({
      'X-Custom-Token': 'tok123',
      'X-Request-Id': 'req-1',
    });
    const creator = createCustomFetch({ strategy: 'custom', getHeaders });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('X-Custom-Token')).toBe('tok123');
    expect(headers.get('X-Request-Id')).toBe('req-1');
  });

  it('passes correct context to getHeaders', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const getHeaders = vi.fn().mockResolvedValue({});
    const context = {
      fetch: mockFetch,
      method: 'POST',
      path: '/users',
      baseUrl: 'https://api.example.com',
    };
    const creator = createCustomFetch({ strategy: 'custom', getHeaders });
    const authFetch = creator(mockFetch, context);

    await authFetch('https://api.example.com/users', { method: 'POST' });

    const callContext = getHeaders.mock.calls[0][0];
    expect(callContext.method).toBe('POST');
    expect(callContext.path).toBe('/users');
    expect(callContext.baseUrl).toBe('https://api.example.com');
    expect(callContext.url).toBe('https://api.example.com/users');
  });

  it('supports synchronous getHeaders', async () => {
    const mockFetch = vi.fn().mockResolvedValue(ok200());
    const creator = createCustomFetch({
      strategy: 'custom',
      getHeaders: () => ({ 'X-Sync': 'yes' }),
    });
    const authFetch = creator(mockFetch, fakeContext());

    await authFetch('https://api.example.com/data', {});

    const headers = mockFetch.mock.calls[0][1].headers as Headers;
    expect(headers.get('X-Sync')).toBe('yes');
  });
});
