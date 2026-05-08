/**
 * Playwright global setup — runs once before all tests.
 *
 * Seeds the test user directly in postgres so the E2E suite does not
 * depend on the registration API endpoint (which can be broken by a
 * passlib/bcrypt version incompatibility in the Docker backend image).
 */

import { Client } from 'pg'
import bcrypt from 'bcryptjs'
import { randomUUID } from 'crypto'

const DB_URL = process.env.DB_URL ?? 'postgresql://postgres:postgres@localhost:5432/asstut'
export const TEST_EMAIL = 'e2e-test@example.com'
export const TEST_PASSWORD = 'testpassword123'

export default async function globalSetup() {
  const client = new Client({ connectionString: DB_URL })
  await client.connect()

  // Check if the test user already exists
  const existing = await client.query('SELECT id FROM users WHERE email = $1', [TEST_EMAIL])
  if (existing.rowCount === 0) {
    const hash = await bcrypt.hash(TEST_PASSWORD, 10)
    await client.query(
      'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)',
      [randomUUID(), TEST_EMAIL, hash],
    )
    console.log(`[global-setup] Created test user: ${TEST_EMAIL}`)
  } else {
    console.log(`[global-setup] Test user already exists: ${TEST_EMAIL}`)
  }

  await client.end()
}
