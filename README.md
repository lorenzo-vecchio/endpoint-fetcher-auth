# @endpoint-fetcher/auth

An authentication plugin for [endpoint-fetcher](https://endpoint-fetcher.lorenzovecchio.dev/) supporting JWT, OAuth2, API Key, Basic, Bearer, HMAC, Digest, and Custom strategies.

## Installation

```bash
npm install @endpoint-fetcher/auth
```

*Requires `endpoint-fetcher` ^3.0.0*

## Quick Start

```typescript
import { createApiClient, get } from 'endpoint-fetcher';
import { auth } from '@endpoint-fetcher/auth';

const api = createApiClient({
  getMe: get<void, User>('/me'),
}, {
  baseUrl: 'https://api.example.com',
  plugins: [
    auth({
      strategy: 'jwt',
      token: localStorage.getItem('access_token') ?? undefined,
      refreshCallback: async (rt) => {
        const res = await fetch('/auth/refresh', {
          method: 'POST',
          body: JSON.stringify({ refresh_token: rt }),
        });
        const data = await res.json();
        return { token: data.access_token, refreshToken: data.refresh_token };
      },
    }),
  ] as const,
});

const me = await api.getMe(); // User — return type is unchanged
```

## Strategies

Select a strategy with the `strategy` field:

| Strategy | Description |
|----------|-------------|
| `jwt` | `Authorization: Bearer <token>` with auto-refresh on 401 |
| `oauth2` | Client Credentials, Authorization Code + PKCE, Device Code |
| `api-key` | Key attached as a header or query parameter |
| `basic` | `Authorization: Basic <base64(user:pass)>` per RFC 7617 |
| `bearer` | Generic bearer token — static, dynamic, or storage-backed |
| `hmac` | HMAC-signed requests (SHA-256 default) via Web Crypto |
| `digest` | Full challenge-response flow per RFC 7616 |
| `custom` | Attach any headers returned from a `getHeaders` callback |

### JWT

```typescript
auth({
  strategy: 'jwt',
  token: 'access-token',
  refreshToken: 'refresh-token',
  refreshCallback: async (rt) => ({ token: await getNewToken(rt) }),
  // or: refreshEndpoint: '/auth/refresh'
})
```

### OAuth2

```typescript
// Client Credentials (server-to-server)
auth({
  strategy: 'oauth2',
  grantType: 'client_credentials',
  clientId: process.env.CLIENT_ID!,
  clientSecret: process.env.CLIENT_SECRET!,
  tokenEndpoint: 'https://auth.example.com/token',
})

// Authorization Code + PKCE (browser)
auth({
  strategy: 'oauth2',
  grantType: 'authorization_code',
  clientId: 'my-spa',
  tokenEndpoint: 'https://auth.example.com/token',
  authorizationEndpoint: 'https://auth.example.com/authorize',
  redirectUri: 'https://myapp.com/callback',
  usePkce: true,
})

// Device Code (CLI / headless)
auth({
  strategy: 'oauth2',
  grantType: 'device_code',
  clientId: 'my-cli',
  tokenEndpoint: 'https://auth.example.com/token',
  deviceAuthorizationEndpoint: 'https://auth.example.com/device/code',
  onDeviceAuthorization: ({ verificationUri, userCode }) => {
    console.log(`Visit ${verificationUri} and enter: ${userCode}`);
  },
})
```

### API Key

```typescript
auth({ strategy: 'api-key', key: 'sk-abc123' })                              // X-API-Key header
auth({ strategy: 'api-key', key: 'sk-abc123', in: 'query', name: 'token' }) // query param
```

### Basic

```typescript
auth({ strategy: 'basic', username: 'alice', password: 's3cr3t' })
auth({ strategy: 'basic', getCredentials: async () => vault.getCredentials() })
```

### Bearer

```typescript
auth({ strategy: 'bearer', token: 'my-opaque-token' })
auth({ strategy: 'bearer', getToken: () => tokenService.getCurrent() })
```

### HMAC

```typescript
auth({
  strategy: 'hmac',
  secret: process.env.HMAC_SECRET!,
  header: 'X-Signature',
  includeBodyHash: true,
})
```

### Custom

```typescript
auth({
  strategy: 'custom',
  getHeaders: async ({ url }) => ({
    'X-Service-Token': await tokenService.get(url),
  }),
})
```

## Token Storage

Strategies that manage tokens accept a `storage` option:

| Adapter | Description |
|---------|-------------|
| `MemoryTokenStorage` | Default — cleared on reload |
| `LocalStorageTokenStorage` | Persists in `localStorage` (browser) |
| `CookieTokenStorage` | Cookie-based; supports SSR callbacks |

```typescript
import { auth, LocalStorageTokenStorage, CookieTokenStorage } from '@endpoint-fetcher/auth';

auth({ strategy: 'jwt', storage: new LocalStorageTokenStorage({ prefix: 'myapp_' }) })

// SSR (e.g. Next.js)
auth({
  strategy: 'jwt',
  storage: new CookieTokenStorage({
    getCookie: (name) => cookies().get(name)?.value ?? null,
    setCookie: (name, value, opts) => cookies().set(name, value, opts),
    deleteCookie: (name) => cookies().delete(name),
  }),
})
```

Implement `TokenStorage` to use any backend:

```typescript
import type { TokenStorage } from '@endpoint-fetcher/auth';

class RedisTokenStorage implements TokenStorage {
  get(key: string)               { return redis.get(key); }
  set(key: string, value: string){ redis.set(key, value); }
  delete(key: string)            { redis.del(key); }
  clear()                        { /* custom */ }
}
```

## Plugin Methods

Accessible via `client.plugins.auth`:

| Method | Description |
|--------|-------------|
| `setToken(token)` | Store an access token |
| `getToken()` | Retrieve the current access token |
| `setRefreshToken(token)` | Store a refresh token |
| `getRefreshToken()` | Retrieve the current refresh token |
| `logout()` | Clear all stored tokens |
| `isAuthenticated()` | `true` if an access token is present |

```typescript
api.plugins.auth.setToken(loginResponse.accessToken);
api.plugins.auth.isAuthenticated(); // true
api.plugins.auth.logout();
```

## Development

```bash
npm install
npm run build
npm run watch
npm test
```

## License

MIT
