import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startBackground, startPage } from './helpers/webauthn.mjs';

// The authenticator rejects with a chosen DOMException; the real background,
// dispatcher and injector must preserve its name and message for the page.
const MESSAGE = 'A passkey for this account already exists.';
let outcome;
let authenticatorCalls = 0;
const browser = startBackground({
  async createCredential() { authenticatorCalls++; throw new DOMException(MESSAGE, outcome); },
  async handleGetAssertion() { authenticatorCalls++; throw new DOMException(MESSAGE, outcome); },
  async getAvailableCredentials() {
    return [{ uniqueId: 'credential-1', username: 'alice', creationTime: 1 }];
  },
});

function frontend() {
  const metrics = { nativeCalls: 0, popupCalls: 0 };
  const { navigator, posts } = startPage({
    browser,
    native: {
      async create() { metrics.nativeCalls++; return null; },
      async get() { metrics.nativeCalls++; return null; },
    },
    async showPopup(_payload, onAction) {
      metrics.popupCalls++;
      return onAction('credential-1');
    },
  });
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
