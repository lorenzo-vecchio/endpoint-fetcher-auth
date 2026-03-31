/**
 * Type-level tests for endpoint-fetcher-auth.
 *
 * This file is not a Vitest test file; it validates compile-time type
 * correctness. If it compiles without errors, the types are correct.
 */

import { auth, MemoryTokenStorage, LocalStorageTokenStorage, CookieTokenStorage } from './src/index';
import type {
  AuthPluginConfig,
  JwtAuthConfig,
  OAuth2AuthConfig,
  ApiKeyAuthConfig,
  BasicAuthConfig,
  BearerAuthConfig,
  HmacAuthConfig,
  DigestAuthConfig,
  CustomAuthConfig,
  TokenStorage,
  AuthPluginMethods,
} from './src/index';
import { createApiClient, get, post } from 'endpoint-fetcher';

// ---------------------------------------------------------------------------
// Test 1: Plugin creation returns correct name
// ---------------------------------------------------------------------------

const bearerPlugin = auth({ strategy: 'bearer', token: 'tok' });
const _name: 'auth' = bearerPlugin.name; // must be literal 'auth'
console.log('Plugin name:', _name);

// ---------------------------------------------------------------------------
// Test 2: All strategies are accepted by AuthPluginConfig
// ---------------------------------------------------------------------------

const jwtConfig: JwtAuthConfig = {
  strategy: 'jwt',
  token: 'access',
  refreshToken: 'refresh',
  autoRefresh: true,
};

const oauth2Config: OAuth2AuthConfig = {
  strategy: 'oauth2',
  grantType: 'client_credentials',
  clientId: 'id',
  clientSecret: 'secret',
  tokenEndpoint: 'https://auth.example.com/token',
};

const apiKeyConfig: ApiKeyAuthConfig = {
  strategy: 'api-key',
  key: 'sk-123',
  in: 'header',
  name: 'X-API-Key',
};

const basicConfig: BasicAuthConfig = {
  strategy: 'basic',
  username: 'user',
  password: 'pass',
};

const bearerConfig: BearerAuthConfig = {
  strategy: 'bearer',
  token: 'tok',
};

const hmacConfig: HmacAuthConfig = {
  strategy: 'hmac',
  secret: 'sec',
  algorithm: 'SHA-256',
  header: 'X-Sig',
};

const digestConfig: DigestAuthConfig = {
  strategy: 'digest',
  username: 'alice',
  password: 'pass',
};

const customConfig: CustomAuthConfig = {
  strategy: 'custom',
  getHeaders: () => ({ 'X-Custom': 'val' }),
};

// All are assignable to the discriminated union
const configs: AuthPluginConfig[] = [
  jwtConfig, oauth2Config, apiKeyConfig, basicConfig,
  bearerConfig, hmacConfig, digestConfig, customConfig,
];
console.log('Config count:', configs.length);

// ---------------------------------------------------------------------------
// Test 3: TypeScript narrows strategy configs correctly
// ---------------------------------------------------------------------------

function handleConfig(c: AuthPluginConfig): string {
  if (c.strategy === 'jwt') return c.refreshEndpoint ?? 'no-refresh';
  if (c.strategy === 'oauth2') return c.clientId;
  if (c.strategy === 'api-key') return c.key;
  if (c.strategy === 'basic') return c.username ?? 'anon';
  if (c.strategy === 'bearer') return c.token ?? 'no-token';
  if (c.strategy === 'hmac') return c.secret;
  if (c.strategy === 'digest') return c.username;
  if (c.strategy === 'custom') return 'custom';
  // TypeScript should infer this as never
  const _exhaustive: never = c;
  return _exhaustive;
}
console.log('Narrowing test:', handleConfig(jwtConfig));

// ---------------------------------------------------------------------------
// Test 4: TokenStorage interface is satisfied by all adapters
// ---------------------------------------------------------------------------

const storages: TokenStorage[] = [
  new MemoryTokenStorage(),
  new LocalStorageTokenStorage({ prefix: 'test_' }),
  new CookieTokenStorage({ prefix: 'test_' }),
];
console.log('Storage count:', storages.length);

// ---------------------------------------------------------------------------
// Test 5: createApiClient with auth plugin provides typed methods
// ---------------------------------------------------------------------------

declare const mockFetch: typeof fetch;

const api = createApiClient(
  {
    getMe: get<void, { id: number; email: string }>('/me'),
    createUser: post<{ name: string }, { id: number }>('/users'),
  },
  {
    baseUrl: 'https://api.example.com',
    fetch: mockFetch,
    plugins: [auth({ strategy: 'bearer' })] as const,
  },
);

// Test that plugin methods are type-safe
const _methods: AuthPluginMethods = api.plugins.auth;
api.plugins.auth.setToken('tok');
api.plugins.auth.setRefreshToken('rt');
const _token: string | null = api.plugins.auth.getToken();
const _refresh: string | null = api.plugins.auth.getRefreshToken();
const _authed: boolean = api.plugins.auth.isAuthenticated();
api.plugins.auth.logout();

// Endpoint return types should NOT be wrapped (unlike cache plugin)
api.getMe().then((result: { id: number; email: string }) => {
  const id: number = result.id;
  const email: string = result.email;
  console.log(id, email);
});

api.createUser({ name: 'Alice' }).then((result: { id: number }) => {
  const id: number = result.id;
  console.log(id);
});

// ---------------------------------------------------------------------------
// Test 6: JWT plugin with all options
// ---------------------------------------------------------------------------

const jwtApi = createApiClient(
  { getData: get<void, { data: string }>('/data') },
  {
    baseUrl: 'https://api.example.com',
    fetch: mockFetch,
    plugins: [
      auth({
        strategy: 'jwt',
        token: 'initial',
        refreshToken: 'initial-refresh',
        refreshCallback: async (rt: string) => ({ token: 'new', refreshToken: rt }),
        storage: new MemoryTokenStorage(),
        tokenStorageKey: 'my_access_token',
        refreshTokenStorageKey: 'my_refresh_token',
        autoRefresh: true,
      }),
    ] as const,
  },
);
console.log('JWT api:', !!jwtApi);

// ---------------------------------------------------------------------------
// Test 7: OAuth2 config discriminated by grantType
// ---------------------------------------------------------------------------

const ccApi = createApiClient(
  { getData: get<void, unknown>('/data') },
  {
    baseUrl: 'https://api.example.com',
    fetch: mockFetch,
    plugins: [
      auth({
        strategy: 'oauth2',
        grantType: 'client_credentials',
        clientId: 'cid',
        clientSecret: 'csecret',
        tokenEndpoint: 'https://auth.example.com/token',
        scope: 'read',
      }),
    ],
  },
);
console.log('CC api:', !!ccApi);

// ---------------------------------------------------------------------------
// Test 8: HMAC config type safety
// ---------------------------------------------------------------------------

const hmacPlugin = auth({
  strategy: 'hmac',
  secret: 'my-secret',
  algorithm: 'SHA-256', // must be 'SHA-1' | 'SHA-256' | 'SHA-512'
  header: 'X-Signature',
  includeTimestamp: true,
  timestampHeader: 'X-Timestamp',
  includeBodyHash: false,
});
console.log('HMAC plugin:', hmacPlugin.name);

// ---------------------------------------------------------------------------
// Test 9: Custom strategy type safety
// ---------------------------------------------------------------------------

const customPlugin = auth({
  strategy: 'custom',
  getHeaders: async (ctx: { method: string; path: string; baseUrl: string; url: string }) => ({
    'X-Method': ctx.method,
    'X-Path': ctx.path,
  }),
});
console.log('Custom plugin:', customPlugin.name);

console.log('All type tests passed!');
