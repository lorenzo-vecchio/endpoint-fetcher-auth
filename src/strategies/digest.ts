import type { DigestAuthConfig, HandlerContext } from '../types';

// ---------------------------------------------------------------------------
// Pure-JS MD5 (RFC 1321) — used for Digest Auth compatibility
// ---------------------------------------------------------------------------

const T = new Int32Array(64);
for (let i = 0; i < 64; i++) T[i] = (Math.floor(2 ** 32 * Math.abs(Math.sin(i + 1)))) | 0;

const S = [
   7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
   5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
   4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
   6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
];

function rotl32(x: number, n: number): number {
  return (x << n) | (x >>> (32 - n));
}

function add32(a: number, b: number): number {
  return (a + b) | 0;
}

/** @internal Pure-JS MD5 returning lowercase hex. */
export function md5(input: string): string {
  // Encode to UTF-8 bytes
  const bytes: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c < 0x80) {
      bytes.push(c);
    } else if (c < 0x800) {
      bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else {
      bytes.push(
        0xe0 | (c >> 12),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f),
      );
    }
  }

  const origBitLen = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0x00);
  // Append length as 64-bit LE integer
  for (let i = 0; i < 8; i++) bytes.push((origBitLen / 2 ** (i * 8)) & 0xff);

  let [a, b, c, d] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

  for (let blk = 0; blk < bytes.length; blk += 64) {
    const M = new Int32Array(16);
    for (let j = 0; j < 16; j++) {
      M[j] =
        (bytes[blk + j * 4]) |
        (bytes[blk + j * 4 + 1] << 8) |
        (bytes[blk + j * 4 + 2] << 16) |
        (bytes[blk + j * 4 + 3] << 24);
    }

    let [aa, bb, cc, dd] = [a, b, c, d];

    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) {
        f = (bb & cc) | (~bb & dd);
        g = i;
      } else if (i < 32) {
        f = (dd & bb) | (~dd & cc);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = bb ^ cc ^ dd;
        g = (3 * i + 5) % 16;
      } else {
        f = cc ^ (bb | ~dd);
        g = (7 * i) % 16;
      }
      const temp = dd;
      dd = cc;
      cc = bb;
      bb = add32(bb, rotl32(add32(add32(add32(aa, f), M[g]), T[i]), S[i]));
      aa = temp;
    }

    a = add32(a, aa);
    b = add32(b, bb);
    c = add32(c, cc);
    d = add32(d, dd);
  }

  // Output as little-endian hex
  let hex = '';
  for (const word of [a, b, c, d]) {
    hex += ((word & 0xff)).toString(16).padStart(2, '0');
    hex += (((word >>> 8) & 0xff)).toString(16).padStart(2, '0');
    hex += (((word >>> 16) & 0xff)).toString(16).padStart(2, '0');
    hex += (((word >>> 24) & 0xff)).toString(16).padStart(2, '0');
  }
  return hex;
}

// ---------------------------------------------------------------------------
// SHA-256 via Web Crypto (for algorithm=SHA-256 in Digest auth)
// ---------------------------------------------------------------------------

async function sha256Hex(input: string): Promise<string> {
  const subtle = (globalThis.crypto ?? (globalThis as any).webcrypto)?.subtle;
  if (!subtle) throw new Error('SubtleCrypto not available for SHA-256 Digest auth.');
  const buf = await subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Digest challenge parsing
// ---------------------------------------------------------------------------

interface DigestChallenge {
  realm: string;
  nonce: string;
  algorithm: string;
  qop?: string;
  opaque?: string;
}

function parseDigestChallenge(wwwAuth: string): DigestChallenge {
  const params: Record<string, string> = {};
  const re = /(\w+)="?([^",]*)"?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(wwwAuth)) !== null) {
    params[m[1].toLowerCase()] = m[2];
  }
  return {
    realm: params['realm'] ?? '',
    nonce: params['nonce'] ?? '',
    algorithm: (params['algorithm'] ?? 'MD5').toUpperCase(),
    qop: params['qop'],
    opaque: params['opaque'],
  };
}

function generateNonce(): string {
  const arr = new Uint8Array(16);
  (globalThis.crypto ?? (globalThis as any).webcrypto).getRandomValues(arr);
  return Array.from(arr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function computeDigestHeader(
  username: string,
  password: string,
  challenge: DigestChallenge,
  method: string,
  uri: string,
  nc: string,
  cnonce: string,
): Promise<string> {
  const { realm, nonce, algorithm, qop, opaque } = challenge;
  const useSha256 = algorithm.startsWith('SHA-256');
  const hashFn = useSha256
    ? (s: string) => sha256Hex(s)
    : (s: string) => Promise.resolve(md5(s));

  let ha1 = await hashFn(`${username}:${realm}:${password}`);
  if (algorithm.endsWith('-SESS')) {
    ha1 = await hashFn(`${ha1}:${nonce}:${cnonce}`);
  }

  const ha2 = await hashFn(`${method.toUpperCase()}:${uri}`);

  let response: string;
  if (qop === 'auth' || qop === 'auth-int') {
    response = await hashFn(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
  } else {
    response = await hashFn(`${ha1}:${nonce}:${ha2}`);
  }

  let header =
    `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", ` +
    `algorithm=${algorithm}, response="${response}"`;
  if (qop) header += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (opaque) header += `, opaque="${opaque}"`;

  return header;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Creates a fetch wrapper that implements HTTP Digest authentication (RFC 7616).
 *
 * Flow:
 * 1. Sends the original request without auth credentials.
 * 2. If the server responds with `401 WWW-Authenticate: Digest ...`, parses
 *    the challenge (realm, nonce, algorithm, qop, opaque).
 * 3. Computes `HA1`, `HA2`, and the response digest.
 * 4. Retries the request with `Authorization: Digest ...`.
 *
 * Supports `algorithm=MD5`, `MD5-sess`, `SHA-256`, and `SHA-256-sess`;
 * and `qop=auth`.
 *
 * @param config - Digest auth strategy configuration.
 * @returns A function that wraps a `fetch` instance with Digest auth logic.
 *
 * @example
 * ```typescript
 * import { auth } from 'endpoint-fetcher-auth';
 *
 * const api = createApiClient({ ... }, {
 *   plugins: [
 *     auth({ strategy: 'digest', username: 'alice', password: 's3cr3t' }),
 *   ] as const,
 * });
 * ```
 */
export function createDigestFetch(
  config: DigestAuthConfig,
): (originalFetch: typeof fetch, context: HandlerContext) => typeof fetch {
  // Track nonce counts per nonce value to support nc incrementing
  const nonceCounts = new Map<string, number>();

  return (originalFetch: typeof fetch, _context: HandlerContext): typeof fetch => {
    return async (input, init) => {
      // First attempt without auth
      const response = await originalFetch(input, init);

      if (response.status !== 401) return response;

      const wwwAuth = response.headers.get('WWW-Authenticate') ?? '';
      if (!wwwAuth.toLowerCase().startsWith('digest ')) return response;

      const challenge = parseDigestChallenge(wwwAuth);
      const nc = ((nonceCounts.get(challenge.nonce) ?? 0) + 1);
      nonceCounts.set(challenge.nonce, nc);
      const ncStr = nc.toString(16).padStart(8, '0');
      const cnonce = generateNonce();

      const rawUrl = input instanceof Request ? input.url : String(input);
      const parsedUrl = new URL(rawUrl);
      const uri = parsedUrl.pathname + parsedUrl.search;
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET');

      const digestHeader = await computeDigestHeader(
        config.username,
        config.password,
        challenge,
        method,
        uri,
        ncStr,
        cnonce,
      );

      const headers = new Headers(init?.headers);
      headers.set('Authorization', digestHeader);

      return originalFetch(input, { ...init, headers });
    };
  };
}
