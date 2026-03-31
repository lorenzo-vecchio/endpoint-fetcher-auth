/**
 * Token storage interface — implement this to provide custom storage backends.
 *
 * @example
 * ```typescript
 * class RedisTokenStorage implements TokenStorage {
 *   constructor(private client: RedisClient, private prefix = 'auth:') {}
 *   get(key: string) { return this.client.get(this.prefix + key); }
 *   set(key: string, value: string) { return this.client.set(this.prefix + key, value); }
 *   delete(key: string) { return this.client.del(this.prefix + key); }
 *   clear() { /* custom clear logic *\/ }
 * }
 * ```
 */
export interface TokenStorage {
  /** Retrieve a stored value by key, or null if absent. */
  get(key: string): string | null;
  /** Store a value under the given key. */
  set(key: string, value: string): void;
  /** Remove a specific key from storage. */
  delete(key: string): void;
  /** Remove all stored values (used by logout). */
  clear(): void;
}

// ---------------------------------------------------------------------------
// JWT strategy
// ---------------------------------------------------------------------------

/**
 * Configuration for the JWT Bearer authentication strategy.
 *
 * Attaches `Authorization: Bearer <token>` to every request.
 * Optionally auto-refreshes the token on 401 responses.
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'jwt',
 *   token: localStorage.getItem('access_token') ?? undefined,
 *   refreshToken: localStorage.getItem('refresh_token') ?? undefined,
 *   refreshCallback: async (rt) => {
 *     const res = await fetch('/auth/refresh', {
 *       method: 'POST',
 *       body: JSON.stringify({ refresh_token: rt }),
 *     });
 *     const data = await res.json();
 *     return { token: data.access_token, refreshToken: data.refresh_token };
 *   },
 * })
 * ```
 */
export type JwtAuthConfig = {
  strategy: 'jwt';
  /** Initial access token written to storage at plugin creation. */
  token?: string;
  /** Initial refresh token written to storage at plugin creation. */
  refreshToken?: string;
  /**
   * URL to POST `{ refresh_token }` to when the access token expires (401).
   * The endpoint must return `{ access_token, refresh_token? }`.
   */
  refreshEndpoint?: string;
  /**
   * Custom async callback to obtain a new token given the current refresh token.
   * Takes precedence over `refreshEndpoint`.
   */
  refreshCallback?: (refreshToken: string) => Promise<{ token: string; refreshToken?: string }>;
  /** Storage adapter — defaults to `MemoryTokenStorage`. */
  storage?: TokenStorage;
  /** Key used to store the access token. @default 'token' */
  tokenStorageKey?: string;
  /** Key used to store the refresh token. @default 'refreshToken' */
  refreshTokenStorageKey?: string;
  /** Automatically refresh the token on 401. @default true */
  autoRefresh?: boolean;
};

// ---------------------------------------------------------------------------
// OAuth2 strategy
// ---------------------------------------------------------------------------

/**
 * Information returned during the OAuth2 Device Authorization flow.
 */
export type DeviceAuthorizationInfo = {
  /** The device verification code (opaque, sent to token endpoint). */
  deviceCode: string;
  /** Short code the user enters at `verificationUri`. */
  userCode: string;
  /** URL where the user authenticates. */
  verificationUri: string;
  /** Convenience URL with `user_code` pre-filled (if provided by server). */
  verificationUriComplete?: string;
  /** Seconds until the device code expires. */
  expiresIn: number;
  /** Minimum polling interval in seconds. */
  interval: number;
};

type OAuth2Base = {
  strategy: 'oauth2';
  /** OAuth2 client identifier. */
  clientId: string;
  /** Token endpoint URL (e.g. `https://auth.example.com/oauth/token`). */
  tokenEndpoint: string;
  /** Storage adapter — defaults to `MemoryTokenStorage`. */
  storage?: TokenStorage;
  /** Key used to store the access token. @default 'token' */
  tokenStorageKey?: string;
  /** Key used to store the refresh token. @default 'refreshToken' */
  refreshTokenStorageKey?: string;
};

/**
 * OAuth2 Client Credentials grant — fully automatic server-to-server flow.
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'oauth2',
 *   grantType: 'client_credentials',
 *   clientId: 'my-service',
 *   clientSecret: process.env.CLIENT_SECRET!,
 *   tokenEndpoint: 'https://auth.example.com/oauth/token',
 *   scope: 'read write',
 * })
 * ```
 */
export type OAuth2ClientCredentialsConfig = OAuth2Base & {
  grantType: 'client_credentials';
  /** Client secret — required for this grant type. */
  clientSecret: string;
  /** Space-separated list of requested scopes. */
  scope?: string;
};

/**
 * OAuth2 Authorization Code + PKCE grant.
 *
 * The plugin uses any token already in storage; call `setToken()` after
 * completing the browser redirect flow, or provide `onUnauthenticated` to
 * trigger the redirect.
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'oauth2',
 *   grantType: 'authorization_code',
 *   clientId: 'my-spa',
 *   tokenEndpoint: 'https://auth.example.com/oauth/token',
 *   authorizationEndpoint: 'https://auth.example.com/oauth/authorize',
 *   redirectUri: 'https://myapp.com/callback',
 *   scope: 'openid profile',
 *   usePkce: true,
 *   onUnauthenticated: () => { window.location.href = buildAuthUrl(...); },
 * })
 * ```
 */
export type OAuth2AuthorizationCodeConfig = OAuth2Base & {
  grantType: 'authorization_code';
  /** Client secret (optional when using PKCE). */
  clientSecret?: string;
  /** Redirect URI registered with the authorization server. */
  redirectUri: string;
  /** Authorization endpoint URL. */
  authorizationEndpoint: string;
  /** Space-separated list of requested scopes. */
  scope?: string;
  /** Enable PKCE (Proof Key for Code Exchange). @default true */
  usePkce?: boolean;
  /** Called when no token is present — use this to initiate the auth redirect. */
  onUnauthenticated?: () => void;
};

/**
 * OAuth2 Device Authorization grant — for headless / CLI flows.
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'oauth2',
 *   grantType: 'device_code',
 *   clientId: 'my-cli',
 *   tokenEndpoint: 'https://auth.example.com/oauth/token',
 *   deviceAuthorizationEndpoint: 'https://auth.example.com/oauth/device/code',
 *   scope: 'read',
 *   onDeviceAuthorization: (info) => {
 *     console.log(`Visit ${info.verificationUri} and enter code: ${info.userCode}`);
 *   },
 * })
 * ```
 */
export type OAuth2DeviceCodeConfig = OAuth2Base & {
  grantType: 'device_code';
  /** Device authorization endpoint URL. */
  deviceAuthorizationEndpoint: string;
  /** Space-separated list of requested scopes. */
  scope?: string;
  /** Called with device flow info so the caller can prompt the user. */
  onDeviceAuthorization: (info: DeviceAuthorizationInfo) => void;
  /** Polling interval override in ms. @default 5000 */
  pollingInterval?: number;
};

/** OAuth2 authentication strategy (union of all grant types). */
export type OAuth2AuthConfig =
  | OAuth2ClientCredentialsConfig
  | OAuth2AuthorizationCodeConfig
  | OAuth2DeviceCodeConfig;

// ---------------------------------------------------------------------------
// API Key strategy
// ---------------------------------------------------------------------------

/**
 * Configuration for the API Key authentication strategy.
 *
 * Attaches the key via a named request header or as a query parameter.
 *
 * @example
 * ```typescript
 * // Header (default)
 * auth({ strategy: 'api-key', key: 'sk-abc123' })
 *
 * // Custom header name
 * auth({ strategy: 'api-key', key: 'sk-abc123', in: 'header', name: 'X-Token' })
 *
 * // Query parameter
 * auth({ strategy: 'api-key', key: 'sk-abc123', in: 'query', name: 'token' })
 * ```
 */
export type ApiKeyAuthConfig = {
  strategy: 'api-key';
  /** The API key value. */
  key: string;
  /** Whether to attach the key as a header or query parameter. @default 'header' */
  in?: 'header' | 'query';
  /**
   * Header or query-param name.
   * @default 'X-API-Key' for header, 'api_key' for query
   */
  name?: string;
};

// ---------------------------------------------------------------------------
// Basic Auth strategy
// ---------------------------------------------------------------------------

/**
 * Configuration for the HTTP Basic authentication strategy (RFC 7617).
 *
 * Encodes `username:password` in Base64 and attaches it as
 * `Authorization: Basic <credentials>`.
 *
 * @example
 * ```typescript
 * // Static credentials
 * auth({ strategy: 'basic', username: 'alice', password: 's3cr3t' })
 *
 * // Dynamic credentials
 * auth({
 *   strategy: 'basic',
 *   getCredentials: async () => ({
 *     username: await vault.get('username'),
 *     password: await vault.get('password'),
 *   }),
 * })
 * ```
 */
export type BasicAuthConfig = {
  strategy: 'basic';
  /** Static username. */
  username?: string;
  /** Static password. */
  password?: string;
  /**
   * Async callback that returns credentials on each request.
   * Takes precedence over `username`/`password` when provided.
   */
  getCredentials?: () => { username: string; password: string } | Promise<{ username: string; password: string }>;
};

// ---------------------------------------------------------------------------
// Bearer strategy
// ---------------------------------------------------------------------------

/**
 * Configuration for the generic Bearer token authentication strategy.
 *
 * Unlike the JWT strategy, this makes no assumptions about the token format —
 * it simply attaches `Authorization: Bearer <token>`.
 *
 * @example
 * ```typescript
 * // Static token
 * auth({ strategy: 'bearer', token: 'my-opaque-token' })
 *
 * // Dynamic token fetched on each request
 * auth({ strategy: 'bearer', getToken: () => secretsManager.getToken() })
 *
 * // Token managed via plugin methods
 * const api = createApiClient({ ... }, {
 *   plugins: [auth({ strategy: 'bearer', storage: new MemoryTokenStorage() })] as const,
 * });
 * api.plugins.auth.setToken('new-token');
 * ```
 */
export type BearerAuthConfig = {
  strategy: 'bearer';
  /** Static bearer token. */
  token?: string;
  /**
   * Async callback that returns the token on each request.
   * Takes precedence over `token` and storage.
   */
  getToken?: () => string | null | Promise<string | null>;
  /** Storage adapter — defaults to `MemoryTokenStorage`. */
  storage?: TokenStorage;
  /** Key used to store the bearer token. @default 'token' */
  tokenStorageKey?: string;
};

// ---------------------------------------------------------------------------
// HMAC strategy
// ---------------------------------------------------------------------------

/** Hash algorithm supported by the HMAC strategy. */
export type HmacAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

/**
 * Configuration for the HMAC request signing strategy.
 *
 * Signs each request with HMAC-SHA256 (or a configurable algorithm) using a
 * shared secret and attaches the hex-encoded signature as a request header.
 *
 * The signed string is: `METHOD\nPATH\nTIMESTAMP[\nBODY_SHA256]`
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'hmac',
 *   secret: process.env.HMAC_SECRET!,
 *   algorithm: 'SHA-256',
 *   header: 'X-Signature',
 *   includeTimestamp: true,
 *   timestampHeader: 'X-Timestamp',
 *   includeBodyHash: true,
 * })
 * ```
 */
export type HmacAuthConfig = {
  strategy: 'hmac';
  /** Shared signing secret. */
  secret: string;
  /** HMAC algorithm. @default 'SHA-256' */
  algorithm?: HmacAlgorithm;
  /** Header that carries the HMAC signature. @default 'X-Signature' */
  header?: string;
  /** Whether to include a timestamp in the signed string and as a header. @default true */
  includeTimestamp?: boolean;
  /** Header that carries the request timestamp (Unix seconds). @default 'X-Timestamp' */
  timestampHeader?: string;
  /** Whether to include a SHA-256 hash of the request body in the signed string. @default false */
  includeBodyHash?: boolean;
};

// ---------------------------------------------------------------------------
// Digest strategy
// ---------------------------------------------------------------------------

/**
 * Configuration for the HTTP Digest authentication strategy (RFC 7616).
 *
 * Implements the full challenge-response flow: sends an unauthenticated request
 * to obtain the `WWW-Authenticate: Digest` challenge, then computes and sends
 * the correct `Authorization: Digest` header on a second attempt.
 *
 * Supports `qop=auth` and `algorithm=MD5` (default) / `SHA-256`.
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'digest',
 *   username: 'alice',
 *   password: 's3cr3t',
 * })
 * ```
 */
export type DigestAuthConfig = {
  strategy: 'digest';
  /** Digest username. */
  username: string;
  /** Digest password. */
  password: string;
};

// ---------------------------------------------------------------------------
// Custom strategy
// ---------------------------------------------------------------------------

/** Context passed to the custom strategy's `getHeaders` callback. */
export type CustomAuthContext = {
  /** HTTP method of the request (e.g. 'GET', 'POST'). */
  method: string;
  /** Endpoint path (e.g. '/users/1'). */
  path: string;
  /** Client base URL (e.g. 'https://api.example.com'). */
  baseUrl: string;
  /** Full resolved URL. */
  url: string;
};

/**
 * Configuration for the fully custom authentication strategy.
 *
 * Accepts a `getHeaders` callback that returns any headers to attach to each
 * request, giving you complete control over the authentication flow.
 *
 * @example
 * ```typescript
 * auth({
 *   strategy: 'custom',
 *   getHeaders: async ({ method, path, url }) => ({
 *     'X-Request-Id': crypto.randomUUID(),
 *     'X-Auth-Token': await myTokenService.get(),
 *   }),
 * })
 * ```
 */
export type CustomAuthConfig = {
  strategy: 'custom';
  /** Returns extra headers to attach to every request. */
  getHeaders: (context: CustomAuthContext) => Record<string, string> | Promise<Record<string, string>>;
};

// ---------------------------------------------------------------------------
// Discriminated union
// ---------------------------------------------------------------------------

/**
 * Discriminated union of all supported authentication strategy configurations.
 * TypeScript narrows the correct config type based on the `strategy` field.
 *
 * @example
 * ```typescript
 * const config: AuthPluginConfig = { strategy: 'jwt', token: '...' };
 *
 * if (config.strategy === 'jwt') {
 *   // config is narrowed to JwtAuthConfig here
 *   console.log(config.refreshEndpoint);
 * }
 * ```
 */
export type AuthPluginConfig =
  | JwtAuthConfig
  | OAuth2AuthConfig
  | ApiKeyAuthConfig
  | BasicAuthConfig
  | BearerAuthConfig
  | HmacAuthConfig
  | DigestAuthConfig
  | CustomAuthConfig;

// ---------------------------------------------------------------------------
// Plugin methods type
// ---------------------------------------------------------------------------

/**
 * Methods exposed on the auth plugin via `client.plugins.auth`.
 *
 * @example
 * ```typescript
 * const api = createApiClient({ ... }, {
 *   plugins: [auth({ strategy: 'jwt', ... })] as const,
 * });
 *
 * api.plugins.auth.setToken('new-access-token');
 * api.plugins.auth.setRefreshToken('new-refresh-token');
 * console.log(api.plugins.auth.isAuthenticated()); // true
 * api.plugins.auth.logout(); // clears all tokens
 * ```
 */
export type AuthPluginMethods = {
  /**
   * Store an access token in the configured storage.
   * Subsequent requests will use this token.
   */
  setToken(token: string): void;
  /** Retrieve the current access token, or `null` if none is stored. */
  getToken(): string | null;
  /** Store a refresh token in the configured storage. */
  setRefreshToken(token: string): void;
  /** Retrieve the current refresh token, or `null` if none is stored. */
  getRefreshToken(): string | null;
  /**
   * Clear all stored tokens from the configured storage.
   * After calling this, `isAuthenticated()` returns `false`.
   */
  logout(): void;
  /** Returns `true` if an access token is currently stored. */
  isAuthenticated(): boolean;
};

// ---------------------------------------------------------------------------
// Internal context type (mirrors endpoint-fetcher's handler context)
// ---------------------------------------------------------------------------

import type { HttpMethod } from 'endpoint-fetcher';

/** @internal */
export type HandlerContext = {
  fetch: typeof fetch;
  method: HttpMethod;
  path: string;
  baseUrl: string;
};
