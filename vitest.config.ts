import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    environment: 'node',

    include: ['tests/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts}'],
    exclude: ['node_modules', 'dist', '.git'],

    setupFiles: ['./tests/setup.ts'],

    typecheck: {
      enabled: false,
    },

    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/setup.ts',
        '**/mocks/**',
      ],
      thresholds: {
        lines: 70,
        functions: 65,
        branches: 80,
        statements: 70,
      },
    },

    testTimeout: 10000,

    hookTimeout: 10000,

    silent: false,

    isolate: true,

    alias: {
      '@': resolve(__dirname, './src'),
      '@tests': resolve(__dirname, './tests'),
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@tests': resolve(__dirname, './tests'),
    },
  },
});
