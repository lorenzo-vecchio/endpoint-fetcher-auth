import { vi, beforeAll, afterAll, beforeEach } from 'vitest';
import type { Mock } from 'vitest';

global.fetch = vi.fn() as Mock;

const originalConsole = { ...console };
const mockConsole = {
  log: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
};

beforeAll(() => {
  if (process.env.SILENT_CONSOLE === 'true') {
    Object.assign(console, mockConsole);
  }
});

afterAll(() => {
  Object.assign(console, originalConsole);
  vi.clearAllMocks();
});

beforeEach(() => {
  vi.resetAllMocks();

  (global.fetch as Mock).mockReset();

  (global.fetch as Mock).mockImplementation(async () => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    json: async () => ({}),
    text: async () => '',
    headers: new Headers(),
  }));
});

export const mockFetchResponse = (
  data: unknown,
  options: {
    ok?: boolean;
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
  } = {},
) => {
  const response = {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    statusText: options.statusText ?? 'OK',
    headers: new Headers(options.headers),
    json: async () => data,
    text: async () => JSON.stringify(data),
  };

  (global.fetch as Mock).mockResolvedValue(response);
  return response;
};

export const mockFetchError = (
  error: Error | string,
  options: {
    ok?: boolean;
    status?: number;
    statusText?: string;
  } = {},
) => {
  const response = {
    ok: options.ok ?? false,
    status: options.status ?? 500,
    statusText: options.statusText ?? 'Internal Server Error',
    headers: new Headers(),
    json: async () => ({ error: typeof error === 'string' ? error : error.message }),
    text: async () => (typeof error === 'string' ? error : error.message),
  };

  (global.fetch as Mock).mockResolvedValue(response);
  return response;
};

export const mockDate = (date: string | Date | number) => {
  const d = new Date(date);
  vi.setSystemTime(d);
  return d;
};

export const restoreDate = () => {
  vi.useRealTimers();
};
