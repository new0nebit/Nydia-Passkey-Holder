// Shared harness for integration tests that run the real background listener,
// dispatcher and injector, with only the extension's outer boundaries replaced.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Module, { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';

const require = createRequire(import.meta.url);
const compiled = (name) => fileURLToPath(new URL(`../../.test-build/${name}`, import.meta.url));
const sources = Object.fromEntries(['dispatcher', 'injector'].map((entry) => [
  entry, readFileSync(compiled(`${entry}.js`), 'utf8'),
]));

export const ORIGIN = 'https://login.example.com';
export const quiet = { logDebug() {}, logError() {}, logInfo() {} };
export const domError = require(compiled('utils/domError.js'));

// Loads a compiled module with some of its own imports replaced.
export function loadWithMocks(name, mocks) {
  const file = compiled(name);
  const load = Module._load;
  try {
    Module._load = function(request, parent, isMain) {
      if (parent?.filename === file && request in mocks) return mocks[request];
      return load.call(this, request, parent, isMain);
    };
    return require(file);
  } finally {
    Module._load = load;
  }
}

// Starts the real background listener around the given authenticator and store.
// Messages sent through the returned browser arrive as if from a top-frame tab at
// ORIGIN.
export function startBackground(authenticator, store = { async getRootKeyIfAvailable() { return true; } }) {
  let listener;
  const browser = {
    runtime: {
      getURL(name) { return `chrome-extension://audit/${name}`; },
      onMessage: { addListener(value) { listener = value; } },
      async sendMessage(message) {
        return listener(message, { origin: ORIGIN, frameId: 0, tab: {} });
      },
    },
  };
  loadWithMocks('background.js', {
    'browser-api': browser,
    './authenticator': authenticator,
    './logger': quiet,
    './store': store,
    './sia': {},
    './siteIcons/background': {},
  });
  assert.equal(typeof listener, 'function', 'background listener was not registered');
  return browser;
}

// Runs the real dispatcher and injector in a minimal page at ORIGIN.
// showPopup stands in for the confirmation window, native for the browser's own
// navigator.credentials, and globals for browser interfaces the injector uses.
export function startPage({ browser, showPopup, native, globals = {} }) {
  const listeners = new Set();
  const posts = [];
  const window = {
    ...globals,
    isSecureContext: true,
    location: { origin: ORIGIN, hostname: new URL(ORIGIN).hostname },
    addEventListener(type, callback) { if (type === 'message') listeners.add(callback); },
    removeEventListener(type, callback) { if (type === 'message') listeners.delete(callback); },
    postMessage(data) {
      const copied = structuredClone(data);
      posts.push(copied);
      queueMicrotask(() => {
        for (const callback of [...listeners]) {
          callback({ source: window, origin: ORIGIN, data: copied });
        }
      });
    },
  };
  window.self = window;
  window.top = window;
  const navigator = { credentials: native };
  const document = {
    createElement() { return {}; },
    head: { appendChild() {} },
  };
  const dependencies = {
    'browser-api': browser,
    './logger': quiet,
    './utils/domError': domError,
    './siteIcons/client': { async getPageSiteIcon() { return undefined; } },
    './popup/shadowHost': { showPopup },
  };
  for (const entry of ['dispatcher', 'injector']) {
    runInNewContext(sources[entry], {
      ...globals,
      exports: {}, window, navigator, document,
      DOMException, Error, URL, ArrayBuffer, Uint8Array,
      atob, btoa, console: { info() {}, debug() {} },
      require(name) {
        assert.ok(name in dependencies, `unexpected frontend import: ${name}`);
        return dependencies[name];
      },
    }, { filename: `${entry}.js` });
  }
  return { navigator, listeners, posts };
}
