// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export { auth } from './plugin';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type {
  TokenStorage,
  AuthPluginConfig,
  AuthPluginMethods,
  HandlerContext,
  // JWT
  JwtAuthConfig,
  // OAuth2
  OAuth2AuthConfig,
  OAuth2ClientCredentialsConfig,
  OAuth2AuthorizationCodeConfig,
  OAuth2DeviceCodeConfig,
  DeviceAuthorizationInfo,
  // API Key
  ApiKeyAuthConfig,
  // Basic
  BasicAuthConfig,
  // Bearer
  BearerAuthConfig,
  // HMAC
  HmacAuthConfig,
  HmacAlgorithm,
  // Digest
  DigestAuthConfig,
  // Custom
  CustomAuthConfig,
  CustomAuthContext,
} from './types';

// ---------------------------------------------------------------------------
// Storage adapters
// ---------------------------------------------------------------------------

export { MemoryTokenStorage } from './storage/memory';
export { LocalStorageTokenStorage } from './storage/localStorage';
export type { LocalStorageTokenStorageOptions } from './storage/localStorage';
export { CookieTokenStorage } from './storage/cookie';
export type { CookieOptions, CookieCallbacks, CookieTokenStorageOptions } from './storage/cookie';

// ---------------------------------------------------------------------------
// OAuth2 PKCE utilities
// ---------------------------------------------------------------------------

export {
  generateCodeVerifier,
  generateCodeChallenge,
  buildAuthorizationUrl,
  exchangeCodeForToken,
} from './strategies/oauth2';

// ---------------------------------------------------------------------------
// Default export
// ---------------------------------------------------------------------------

export { auth as default } from './plugin';
