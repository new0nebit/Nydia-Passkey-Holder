import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import Module from 'node:module';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const backgroundPath = fileURLToPath(new URL('../.test-build/background.js', import.meta.url));
const helpers = require('../.test-build/utils/domError.js');
const sources = Object.fromEntries(['dispatcher', 'injector'].map((entry) => [
  entry, readFileSync(new URL(`../.test-build/${entry}.js`, import.meta.url), 'utf8'),
]));
const ORIGIN = 'https://login.example.com';
const MESSAGE = 'A passkey for this account already exists.';
const quiet = { logDebug() {}, logError() {}, logInfo() {} };
let listener;
let outcome;
let authenticatorCalls = 0;
const browser = {
  runtime: {
    getURL(name) { return `chrome-extension://audit/${name}`; },
    onMessage: { addListener(value) { listener = value; } },
    async sendMessage(message) {
      return listener(message, { origin: ORIGIN, frameId: 0, tab: {} });
    },
  },
};
const authenticator = {
  async createCredential() { authenticatorCalls++; throw new DOMException(MESSAGE, outcome); },
  async handleGetAssertion() { authenticatorCalls++; throw new DOMException(MESSAGE, outcome); },
  async getAvailableCredentials() {
    return [{ uniqueId: 'credential-1', username: 'alice', creationTime: 1 }];
  },
};
const boundaries = new Map([
  ['browser-api', browser],
  ['./authenticator', authenticator],
  ['./logger', quiet],
  ['./store', { async getRootKeyIfAvailable() { return true; } }],
  ['./sia', {}],
]);
// The real background listener runs here; no error serialization is reproduced.
const originalLoad = Module._load;
try {
  Module._load = function(request, parent, isMain) {
    if (parent?.filename === backgroundPath && boundaries.has(request)) {
      return boundaries.get(request);
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  require(backgroundPath);
} finally {
  Module._load = originalLoad;
}
assert.equal(typeof listener, 'function');

function frontend() {
  const listeners = new Set();
  const posts = [];
  const metrics = { nativeCalls: 0, popupCalls: 0 };
  const window = {
    isSecureContext: true,
    location: { origin: ORIGIN, hostname: 'login.example.com' },
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
  const navigator = { credentials: {
    async create() { metrics.nativeCalls++; return null; },
    async get() { metrics.nativeCalls++; return null; },
  } };
  const document = {
    createElement() { return { remove() {} }; },
    head: { appendChild() {} },
  };
  const dependencies = {
    'browser-api': browser,
    './logger': quiet,
    './utils/domError': helpers,
    './popup/pageIcon': { async readCachedPageIcon() { return null; } },
    './popup/shadowHost': { async showPopup(_payload, onAction) {
      metrics.popupCalls++;
      return onAction('credential-1');
    } },
  };
  for (const entry of ['dispatcher', 'injector']) {
    runInNewContext(sources[entry], {
      exports: {}, window, navigator, document,
      DOMException, Error, URL, ArrayBuffer, Uint8Array,
      atob, btoa, console: { info() {}, debug() {} },
      require(name) {
        assert.ok(name in dependencies, `unexpected frontend import: ${name}`);
        return dependencies[name];
      },
    }, { filename: `${entry}.js` });
  }
  return { navigator, metrics, posts };
}

for (const [operation, name] of [['create', 'InvalidStateError'], ['get', 'EncodingError']]) {
  test(`${operation}: preserves ${name} from background to the page`, { timeout: 2000 }, async () => {
    outcome = name;
    authenticatorCalls = 0;
    const { navigator, metrics, posts } = frontend();
    const publicKey = { challenge: new Uint8Array([1, 2, 3]) };
    if (operation === 'create') {
      publicKey.rp = { id: 'example.com', name: 'Example' };
      publicKey.user = { id: new Uint8Array([4, 5]), name: 'alice' };
      publicKey.pubKeyCredParams = [{ type: 'public-key', alg: -7 }];
    } else publicKey.rpId = 'example.com';
    await assert.rejects(navigator.credentials[operation]({ publicKey }), (error) => {
      assert.ok(error instanceof DOMException);
      assert.equal(error.name, name);
      assert.equal(error.message, MESSAGE);
      return true;
    });
    assert.equal(authenticatorCalls, 1);
    assert.equal(metrics.popupCalls, 1);
    assert.equal(metrics.nativeCalls, 0);
    const transported = posts.find((message) => message.type === `webauthn-${operation}-error`);
    assert.equal(transported?.errorName, name);
  });
}

test('create: rejects with SecurityError before opening the confirmation window', { timeout: 2000 }, async () => {
  authenticatorCalls = 0;
  const { navigator, metrics } = frontend();
  await assert.rejects(navigator.credentials.create({ publicKey: {
    challenge: new Uint8Array([1]),
    rp: { id: 'bank.example', name: 'Bank' },
    user: { id: new Uint8Array([1]), name: 'alice' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  } }), (error) => {
    assert.ok(error instanceof DOMException);
    assert.equal(error.name, 'SecurityError');
    return true;
  });
  assert.equal(authenticatorCalls, 0);
  assert.equal(metrics.popupCalls, 0);
  assert.equal(metrics.nativeCalls, 0);
});
