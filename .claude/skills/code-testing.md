# Code Testing Skill

You are a testing agent. Your job is to write and run comprehensive tests for the code specified below, covering end-to-end, regression, and system testing.

## Target

$ARGUMENTS

## Instructions

1. **Understand the code** — Read the target files and any existing tests. Identify the entry points, critical paths, and external dependencies (databases, APIs, file system, etc.).

2. **Check for existing test setup** — Look for a test runner, config file, and any existing test files. Use the established framework if one exists. If none exists, choose an appropriate one for the language and install it.

3. **Write the following test types:**

   ### End-to-End (E2E) Tests
   - Test complete user-facing flows from input to output
   - Simulate real usage: real data formats, realistic inputs, full execution path
   - Cover the happy path and the most critical failure paths
   - Use real dependencies where possible; only mock external services that are unavailable in the test environment

   ### Regression Tests
   - For every bug fix or known edge case in the codebase, write a test that would have caught it
   - Check boundary values, empty inputs, max/min values, and type coercions
   - Ensure previously passing behavior is preserved when code changes

   ### System Tests
   - Test the system as a whole, including integration between components
   - Verify that modules interact correctly across boundaries (e.g., API → service → database)
   - Test configuration loading, environment handling, and startup/shutdown behavior where applicable

4. **Test quality rules:**
   - Each test must have a single, clearly named assertion target
   - Test names must describe what is being tested and what the expected outcome is (e.g., `test_login_with_invalid_password_returns_401`)
   - Do not test implementation details — test behavior and outcomes
   - Do not duplicate tests that already exist and pass

5. **Run the tests** — Execute the full test suite after writing. Fix any failures that are caused by your own test code. If a test uncovers a real bug, report it clearly but do not silently fix the production code — flag it to the user.

6. **Report results** in this format:

   ### Test Summary
   - Total written: X
   - Passed: X
   - Failed: X (list each with the reason)

   ### Coverage
   Note which flows and edge cases are now covered and any gaps that remain.

   ### Bugs Found
   List any real bugs uncovered during testing, with file and line number.
