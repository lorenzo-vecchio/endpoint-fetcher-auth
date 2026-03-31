import type { HmacAuthConfig, HmacAlgorithm, HandlerContext } from '../types';

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function getSubtle(): SubtleCrypto {
  const subtle = (globalThis.crypto ?? (globalThis as any).webcrypto)?.subtle;
  if (!subtle) {
    throw new Error(
      'SubtleCrypto is not available. HMAC signing requires Node.js >= 18 or a modern browser.',
    );
  }
  return subtle;
}

async function computeHmac(algorithm: HmacAlgorithm, secret: string, message: string): Promise<string> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const key = await subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );
  const signature = await subtle.sign('HMAC', key, encoder.encode(message));
  return toHex(new Uint8Array(signature));
}

async function hashBody(algorithm: string, body: BodyInit | null | undefined): Promise<string> {
  const subtle = getSubtle();
  let data: ArrayBuffer;

  if (!body) {
    data = new ArrayBuffer(0);
  } else if (typeof body === 'string') {
    data = new TextEncoder().encode(body).buffer as ArrayBuffer;
  } else if (body instanceof ArrayBuffer) {
    data = body;
  } else if (ArrayBuffer.isView(body)) {
    data = body.buffer as ArrayBuffer;
  } else if (body instanceof Blob) {
    data = await body.arrayBuffer();
  } else {
    // URLSearchParams, ReadableStream, FormData — convert to string
    data = new TextEncoder().encode(String(body)).buffer as ArrayBuffer;
  }

  const digest = await subtle.digest(algorithm, data);
  return toHex(new Uint8Array(digest));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Creates a fetch wrapper that signs each request using HMAC.
 *
 * The signed string is composed of (newline-separated):
 * ```
 * METHOD
 * PATH
 * [TIMESTAMP]       — included when includeTimestamp is true (default)
 * [BODY_HASH]       — SHA-256 hex of the request body, when includeBodyHash is true
 * ```
 *
 * The HMAC-SHA256 signature is hex-encoded and attached via the configured header.
 *
 * @param config - HMAC strategy configuration.
 * @returns A function that wraps a `fetch` instance with HMAC signing.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({
 *       strategy: 'hmac',
 *       secret: process.env.HMAC_SECRET!,
 *       algorithm: 'SHA-256',
 *       header: 'X-Signature',
 *       timestampHeader: 'X-Timestamp',
 *       includeBodyHash: true,
 *     }),
 *   ] as const,
 * });
 * ```
 */
export function createHmacFetch(
  config: HmacAuthConfig,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  const algorithm: HmacAlgorithm = config.algorithm ?? 'SHA-256';
  const signatureHeader = config.header ?? 'X-Signature';
  const includeTimestamp = config.includeTimestamp ?? true;
  const timestampHeader = config.timestampHeader ?? 'X-Timestamp';
  const includeBodyHash = config.includeBodyHash ?? false;

  return (originalFetch: typeof fetch, context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      const method = init?.method ?? context.method ?? 'GET';
      const rawUrl = input instanceof Request ? input.url : String(input);
      const parsedUrl = new URL(rawUrl);
      const path = parsedUrl.pathname + parsedUrl.search;
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const parts: string[] = [method.toUpperCase(), path];
      if (includeTimestamp) parts.push(timestamp);

      const body = init?.body ?? (input instanceof Request ? undefined : undefined);
      if (includeBodyHash) {
        const bodyHash = await hashBody(algorithm, body);
        parts.push(bodyHash);
      }

      const messageToSign = parts.join('\n');
      const signature = await computeHmac(algorithm, config.secret, messageToSign);

      const headers = new Headers(init?.headers);
      headers.set(signatureHeader, signature);
      if (includeTimestamp) headers.set(timestampHeader, timestamp);

      return originalFetch(input, { ...init, headers });
    };
  };
}
