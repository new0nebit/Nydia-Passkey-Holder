# Chrome storage regression checks

Build the production Chrome extension and the test modules first:

```sh
npm test
npm run build:chrome
CHROME_PATH='/absolute/path/to/Google Chrome for Testing' \
PLAYWRIGHT_MODULE='/absolute/path/to/playwright-core' \
node tests/browser/storage.mjs
```

Use the Chrome executable inside the application bundle on macOS.
Playwright Core is an external test prerequisite; if it is installed where Node
can resolve it, omit `PLAYWRIGHT_MODULE`.

The script copies the extension into a temporary directory and launches a fresh
headless Chrome profile. It never uses an installed extension's profile or a real
renterd server. The temporary copy grants access to localhost for an HTTP fixture.
The output gives the temporary directory, including a failure screenshot if a
check fails.

Checks cover independently constructed legacy passkeys, new registration and
sign-in, encrypted settings, Test Connection, Backup/Sync, a full browser restart,
damaged settings, plaintext migration and protocol persistence. WebAuthn requests go through `navigator.credentials`, the injected extension,
its confirmation iframe, and the production background. Assertions are verified
with the public key. Confirmation events are dispatched inside the iframe;
pointer/focus behavior is not tested. Settings controls use ordinary clicks.

Backup/Sync use the local HTTP fixture.
