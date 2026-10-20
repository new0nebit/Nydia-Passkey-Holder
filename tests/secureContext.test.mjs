import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

for (const entry of ['dispatcher', 'injector']) {
  test(`${entry} leaves an insecure page untouched`, () => {
    const window = { isSecureContext: false };
    window.self = window;
    window.top = window;
    // The page's own WebAuthn must stay as it was: neither replaced nor called.
    const credentials = Object.freeze({
      create() { throw new Error('Unexpected native create call'); },
      get() { throw new Error('Unexpected native get call'); },
    });
    let documentAccesses = 0;
    const context = {
      window,
      navigator: { credentials },
      exports: {},
      require(name) {
        if (name === './logger') return { logDebug() {} };
        if (name === 'browser-api') return { default: {} };
        if (name === './utils/domError' || name === './popup/shadowHost' || name === './popup/pageIcon') return {};
        throw new Error(`Unexpected import: ${name}`);
      },
      get document() {
        documentAccesses += 1;
        throw new Error('Insecure page must not receive injected UI or scripts');
      },
    };
    const source = readFileSync(new URL(`../.test-build/${entry}.js`, import.meta.url), 'utf8');
    assert.doesNotThrow(() => runInNewContext(source, context));
    assert.equal(documentAccesses, 0);
    assert.equal(context.navigator.credentials, credentials);
  });
}
