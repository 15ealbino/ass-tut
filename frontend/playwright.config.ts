import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: process.env.BASE_URL ?? 'http://localhost:80',
    trace: 'on-first-retry',
    headless: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // Do NOT start the servers automatically — the user runs them separately.
  // Local docker-compose: docker-compose up --build -d  (serves on :80)
  // Oracle VM:            BASE_URL=http://138.2.212.103 npx playwright test
})
