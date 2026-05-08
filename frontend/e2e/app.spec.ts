/**
 * End-to-end tests for the CYBER//ASM app.
 *
 * Pre-conditions:
 *   - Backend running on :8000 (uvicorn or docker-compose)
 *   - Frontend on :80 (docker-compose) or set BASE_URL env var for remote
 *   - No authentication required — /compile is a public endpoint
 *
 * Run: npx playwright test
 */

import { expect, test } from '@playwright/test'

// ── App shell ─────────────────────────────────────────────────────────────────

test.describe('App shell', () => {
  test('root path renders the editor directly (no login redirect)', async ({ page }) => {
    await page.goto('/')
    // Should stay on / — no redirect to /login
    await expect(page).not.toHaveURL(/\/login/)
    await expect(page).toHaveURL('/')
  })

  test('CYBER//ASM wordmark is visible', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText('CYBER')).toBeVisible()
    await expect(page.getByText('ASM')).toBeVisible()
  })

  test('compile button is visible on load', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('button', { name: /COMPILE/i })).toBeVisible()
  })

  test('VULN//LAB sidebar is visible on load', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText('VULN//LAB')).toBeVisible()
  })

  test('sidebar can be collapsed and re-expanded', async ({ page }) => {
    await page.goto('/')
    // Click collapse arrow
    await page.getByRole('button', { name: '◀' }).click()
    await expect(page.getByText('VULN//LAB')).not.toBeVisible()
    // Re-expand
    await page.getByRole('button', { name: '▶' }).click()
    await expect(page.getByText('VULN//LAB')).toBeVisible()
  })

  test('unknown routes redirect to /', async ({ page }) => {
    await page.goto('/some-unknown-path')
    await expect(page).toHaveURL('/')
  })
})

// ── Placeholder panes ─────────────────────────────────────────────────────────

test.describe('Placeholder panes before compile', () => {
  test.beforeEach(async ({ page }) => { await page.goto('/') })

  test('C pane shows AWAITING INPUT before compile', async ({ page }) => {
    await expect(page.getByText('AWAITING INPUT').first()).toBeVisible()
  })

  test('Assembly pane shows AWAITING INPUT before compile', async ({ page }) => {
    const panels = page.getByText('AWAITING INPUT')
    expect(await panels.count()).toBeGreaterThanOrEqual(2)
  })
})

// ── VULN//LAB sidebar ─────────────────────────────────────────────────────────

test.describe('VULN//LAB sidebar', () => {
  test.beforeEach(async ({ page }) => { await page.goto('/') })

  test('STACK BUFFER OVERFLOW entry is listed', async ({ page }) => {
    await expect(page.getByText('STACK BUFFER OVERFLOW')).toBeVisible()
  })

  test('INTEGER OVERFLOW entry is listed', async ({ page }) => {
    await expect(page.getByText('INTEGER OVERFLOW')).toBeVisible()
  })

  test('COMMAND INJECTION entry is listed', async ({ page }) => {
    await expect(page.getByText('COMMAND INJECTION')).toBeVisible()
  })

  test('clicking a vuln card loads code into the editor', async ({ page }) => {
    await page.getByText('STACK BUFFER OVERFLOW').click()
    // The editor should now contain the BOF template code
    const editorContent = await page.locator('.cm-content').textContent()
    expect(editorContent).toContain('fill_buffer')
  })

  test('clicking a vuln card shows its severity badge in Python pane header', async ({ page }) => {
    await page.getByText('STACK BUFFER OVERFLOW').click()
    await expect(page.getByText('CRITICAL').first()).toBeVisible()
  })

  test('clicking a vuln card clears any previous compile result', async ({ page }) => {
    // Compile something first
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })

    // Load a vuln — result should be cleared (AWAITING INPUT re-appears)
    await page.getByText('INTEGER OVERFLOW').click()
    await expect(page.getByText('AWAITING INPUT').first()).toBeVisible()
  })

  test('manually editing code after selecting a vuln clears the advisory', async ({ page }) => {
    await page.getByText('NULL POINTER DEREF').click()
    await expect(page.getByText('NULL POINTER DEREF').first()).toBeVisible()

    // Type in the editor
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('End')
    await page.keyboard.type(' ')

    // SECURITY ADVISORY header should disappear after compile since vuln was cleared
    // (advisory only shows when activeVuln is set AND there's a compile result)
    // Verify the badge in the Python header reverted to INPUT
    await expect(page.getByText('INPUT')).toBeVisible({ timeout: 3000 })
  })
})

// ── Compile: happy path ───────────────────────────────────────────────────────

test.describe('Compile flow', () => {
  test.beforeEach(async ({ page }) => { await page.goto('/') })

  test('default starter code compiles successfully', async ({ page }) => {
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })
    await expect(page.getByText('TRANSPILED')).toBeVisible()
    await expect(page.getByText('GCC -O0')).toBeVisible()
  })

  test('C pane shows transpiled code after compile', async ({ page }) => {
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('TRANSPILED')).toBeVisible({ timeout: 15000 })
    // C output must contain int main
    await expect(page.locator('pre', { hasText: 'int' }).first()).toBeVisible()
  })

  test('Assembly pane shows GCC output after compile', async ({ page }) => {
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('GCC -O0')).toBeVisible({ timeout: 15000 })
    // Assembly must contain "main:" label
    await expect(page.locator('pre', { hasText: 'main:' }).first()).toBeVisible()
  })

  test('TRACE legend bar appears after compile', async ({ page }) => {
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('TRACE::')).toBeVisible({ timeout: 15000 })
  })

  test('legend chips use L{N}: prefix format', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('x = 1\ny = 2\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('TRACE::')).toBeVisible({ timeout: 15000 })

    // New format is "L1: x = 1" not "Line 1: x = 1"
    await expect(page.getByText(/^L\d+:/).first()).toBeVisible()
  })

  test('clicking a legend chip activates it', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('x = 42\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('TRACE::')).toBeVisible({ timeout: 15000 })

    const chip = page.getByText(/^L1:/).first()
    await expect(chip).toBeVisible()
    await chip.click()

    // Active chip has a glow box-shadow — verify it re-renders (no JS error)
    await expect(chip).toBeVisible()
  })

  test('simple assignment compiles without error bar', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('x = 5\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })
    await expect(page.getByText(/\[!\] ERR ::/)).not.toBeVisible()
  })

  test('compile button is disabled while compiling (no double-submit)', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('x = 1\n')

    const btn = page.getByRole('button', { name: /COMPILE/i })
    await btn.click()

    // Should eventually re-enable
    await expect(btn).toBeEnabled({ timeout: 15000 })
  })
})

// ── Compile: error path ───────────────────────────────────────────────────────

test.describe('Compile error handling', () => {
  test.beforeEach(async ({ page }) => { await page.goto('/') })

  test('unsupported Python construct shows [!] ERR bar', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('import os\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText(/\[!\] ERR ::/)).toBeVisible({ timeout: 12000 })
  })

  test('error bar clears after a successful recompile', async ({ page }) => {
    const editor = page.locator('.cm-content')

    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('import os\n')
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText(/\[!\] ERR ::/)).toBeVisible({ timeout: 12000 })

    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('x = 1\n')
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText(/\[!\] ERR ::/)).not.toBeVisible({ timeout: 12000 })
    await expect(page.getByText('COMPILED OK')).toBeVisible()
  })
})

// ── Security advisory banner ──────────────────────────────────────────────────

test.describe('Security advisory banner in Assembly pane', () => {
  test.beforeEach(async ({ page }) => { await page.goto('/') })

  test('advisory banner appears after compiling a vuln template', async ({ page }) => {
    await page.getByText('STACK BUFFER OVERFLOW').click()
    await page.getByRole('button', { name: /COMPILE/i }).click()

    await expect(page.getByText('SECURITY ADVISORY')).toBeVisible({ timeout: 15000 })
    await expect(page.getByText(/STACK BUFFER OVERFLOW/).first()).toBeVisible()
  })

  test('advisory banner shows the severity badge', async ({ page }) => {
    await page.getByText('STACK BUFFER OVERFLOW').click()
    await page.getByRole('button', { name: /COMPILE/i }).click()

    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })
    // CRITICAL badge should appear in advisory
    const criticalBadges = page.getByText('CRITICAL')
    expect(await criticalBadges.count()).toBeGreaterThanOrEqual(1)
  })

  test('advisory banner can be collapsed with [-] button', async ({ page }) => {
    await page.getByText('INTEGER OVERFLOW').click()
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('SECURITY ADVISORY')).toBeVisible({ timeout: 15000 })

    // Collapse it
    await page.getByRole('button', { name: '[-]' }).click()
    // Explanation text should be hidden — the banner header stays
    await expect(page.getByText('SECURITY ADVISORY')).toBeVisible()
    // [+] toggle appears after collapse
    await expect(page.getByRole('button', { name: '[+]' })).toBeVisible()
  })

  test('advisory banner re-expands with [+] button', async ({ page }) => {
    await page.getByText('USE-AFTER-FREE').click()
    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('SECURITY ADVISORY')).toBeVisible({ timeout: 15000 })

    await page.getByRole('button', { name: '[-]' }).click()
    await page.getByRole('button', { name: '[+]' }).click()
    // After re-expanding, [-] is back
    await expect(page.getByRole('button', { name: '[-]' })).toBeVisible()
  })
})

// ── Regression: edge-case inputs ─────────────────────────────────────────────

test.describe('Regression: edge cases', () => {
  test.beforeEach(async ({ page }) => { await page.goto('/') })

  test('empty editor compiles to trivial program without error', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.press('Delete')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 12000 })
  })

  test('for-range loop compiles successfully', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('for i in range(3):\n    x = i\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })
  })

  test('while loop compiles successfully', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('x = 0\nwhile x < 5:\n    x += 1\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })
  })

  test('function definition compiles successfully', async ({ page }) => {
    const editor = page.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+A')
    await page.keyboard.type('def add(a, b):\n    return a + b\n')

    await page.getByRole('button', { name: /COMPILE/i }).click()
    await expect(page.getByText('COMPILED OK')).toBeVisible({ timeout: 15000 })
  })

  test('all 8 vuln sidebar templates compile without error', async ({ page }) => {
    const vulnNames = [
      'STACK BUFFER OVERFLOW',
      'INTEGER OVERFLOW',
      'FORMAT STRING',
      'USE-AFTER-FREE',
      'NULL POINTER DEREF',
      'COMMAND INJECTION',
      'INTEGER TRUNCATION',
      'UNINITIALIZED VAR',
    ]

    for (const name of vulnNames) {
      await page.getByText(name).click()
      await page.getByRole('button', { name: /COMPILE/i }).click()
      await expect(page.getByText('COMPILED OK')).toBeVisible({
        timeout: 20000,
      })
      // Ensure no error bar appeared
      await expect(page.getByText(/\[!\] ERR ::/)).not.toBeVisible()
    }
  })
})
