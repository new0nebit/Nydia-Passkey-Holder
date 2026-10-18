import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { test } from 'node:test';
import { domError, loadWithMocks, quiet, startBackground, startPage } from './helpers/webauthn.mjs';

// Runs the real background listener, dispatcher and injector. The popup window
// is replaced: it either confirms the request or is cancelled. The
// authenticator returns fixed responses, except where a request has to fail
// inside the real one.

const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
const bytesOf = (buffer) => [...new Uint8Array(buffer)];

const RAW_ID = [9, 8, 7, 6];
const CLIENT_DATA = [...Buffer.from('{"type":"webauthn.create"}')];
const ATTESTATION_OBJECT = [0xa3, 0x63, 0x66, 0x6d, 0x74];
const AUTHENTICATOR_DATA = Array.from({ length: 37 }, (_, i) => i);
const PUBLIC_KEY_DER = [0x30, 0x59, 0x30, 0x13];
const SIGNATURE = [0x30, 0x44, 0x02, 0x20];
const USER_HANDLE = [4, 5];

const createResponse = {
  type: 'public-key',
  id: b64(RAW_ID),
  rawId: b64(RAW_ID),
  response: {
    clientDataJSON: b64(CLIENT_DATA),
    attestationObject: b64(ATTESTATION_OBJECT),
    authenticatorData: b64(AUTHENTICATOR_DATA),
    publicKeyAlgorithm: -7,
    publicKeyDER: b64(PUBLIC_KEY_DER),
  },
};
const getResponse = {
  type: 'public-key',
  id: b64(RAW_ID),
  rawId: b64(RAW_ID),
  response: {
    clientDataJSON: b64(CLIENT_DATA),
    authenticatorData: b64(AUTHENTICATOR_DATA),
    signature: b64(SIGNATURE),
    userHandle: b64(USER_HANDLE),
  },
};

// The real authenticator, with storage mocked and logging silenced, for requests
// that must fail inside it rather than in a fixed response.
const realAuthenticator = loadWithMocks('authenticator.js', {
  './store': {
    async createUniqueId(rpId, credentialId) { return `${rpId}:${credentialId}`; },
    async getEncryptedRecord() { return null; },
    async savePrivateKey() { throw new Error('nothing may be stored'); },
  },
  './logger': quiet,
});
let useRealAuthenticator = false;
let authenticatorCalls = 0;
const browser = startBackground({
  async createCredential(options) {
    authenticatorCalls++;
    if (useRealAuthenticator) return realAuthenticator.createCredential(options);
    return structuredClone(createResponse);
  },
  async handleGetAssertion() { authenticatorCalls++; return structuredClone(getResponse); },
  async getAvailableCredentials() {
    return [{ uniqueId: 'credential-1', username: 'alice', creationTime: 1 }];
  },
});

// Stand-ins for the browser's WebAuthn interfaces, so prototype checks have
// something to compare against. The browser's own toJSON() on the prototype
// rejects any object it did not create, as Chrome does with "Illegal invocation".
class PublicKeyCredential {
  toJSON() { throw new TypeError('Illegal invocation'); }
}
class AuthenticatorAttestationResponse {}
class AuthenticatorAssertionResponse {}

function frontend(popup, { real = false } = {}) {
  useRealAuthenticator = real;
  const nativeCalls = [];
  const nativeResult = { native: true };
  const { navigator, listeners } = startPage({
    browser,
    globals: { PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse },
    native: {
      async create(options) { nativeCalls.push({ operation: 'create', options }); return nativeResult; },
      async get(options) { nativeCalls.push({ operation: 'get', options }); return nativeResult; },
    },
    // Mirrors the popup host: an error result or a plain Error stays in the
    // open window, a WebAuthn DOMException ends the request for the page.
    async showPopup(_payload, onAction) {
      if (popup === 'cancel') return 'closed';
      try {
        const result = await onAction('credential-1');
        if (result && typeof result === 'object' && 'error' in result) return new Promise(() => {});
        return result;
      } catch (error) {
        if (domError.isWebAuthnDomException(error)) throw error;
        return new Promise(() => {});
      }
    },
  });
  return { navigator, nativeCalls, nativeResult, listeners };
}

function requestOptions(operation, signal) {
  const publicKey = { challenge: new Uint8Array([1, 2, 3]) };
  if (operation === 'create') {
    publicKey.rp = { id: 'example.com', name: 'Example' };
    publicKey.user = { id: new Uint8Array(USER_HANDLE), name: 'alice' };
    publicKey.pubKeyCredParams = [{ type: 'public-key', alg: -7 }];
  } else publicKey.rpId = 'example.com';
  return { publicKey, signal };
}

for (const operation of ['create', 'get']) {
  test(`cancelling the popup hands ${operation} to the browser with the page's own options`, { timeout: 2000 }, async () => {
    authenticatorCalls = 0;
    const { navigator, nativeCalls, nativeResult, listeners } = frontend('cancel');
    const listenersBefore = listeners.size;
    const signal = new AbortController().signal;
    const options = requestOptions(operation, signal);

    const result = await navigator.credentials[operation](options);

    assert.equal(result, nativeResult, 'the page receives the browser result');
    assert.equal(nativeCalls.length, 1, 'the browser API runs exactly once');
    assert.equal(nativeCalls[0].operation, operation);
    assert.equal(nativeCalls[0].options, options, 'the original options object is passed on');
    assert.equal(nativeCalls[0].options.signal, signal, 'the page signal reaches the browser');
    assert.equal(authenticatorCalls, 0, 'a cancelled request never reaches the authenticator');
    assert.equal(listeners.size, listenersBefore, 'the response listener is removed');
  });
}

test('a created credential exposes the registration data the page reads', { timeout: 2000 }, async () => {
  const { navigator, nativeCalls, listeners } = frontend('confirm');
  const listenersBefore = listeners.size;
  const credential = await navigator.credentials.create(requestOptions('create'));

  assert.equal(nativeCalls.length, 0);
  assert.equal(listeners.size, listenersBefore, 'the response listener is removed');
  assert.ok(credential instanceof PublicKeyCredential);
  assert.equal(credential.type, 'public-key');
  assert.equal(credential.id, b64(RAW_ID));
  assert.ok(credential.rawId instanceof ArrayBuffer);
  assert.deepEqual(bytesOf(credential.rawId), RAW_ID);
  assert.equal(credential.authenticatorAttachment, 'platform');
  // The object comes from another realm, so compare its contents, not its prototype.
  assert.deepEqual(JSON.parse(JSON.stringify(credential.getClientExtensionResults())), { credProps: { rk: true } });

  const { response } = credential;
  assert.ok(response instanceof AuthenticatorAttestationResponse);
  assert.deepEqual(bytesOf(response.clientDataJSON), CLIENT_DATA);
  assert.deepEqual(bytesOf(response.attestationObject), ATTESTATION_OBJECT);
  assert.deepEqual(bytesOf(response.getAuthenticatorData()), AUTHENTICATOR_DATA);
  assert.deepEqual(bytesOf(response.getPublicKey()), PUBLIC_KEY_DER);
  assert.equal(response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual([...response.getTransports()], ['internal', 'hybrid']);
});

// A request listing only algorithms Nydia cannot create must end for the page
// with NotSupportedError, not leave the confirmation window waiting.
test('unsupported algorithms reach the page as NotSupportedError', { timeout: 2000 }, async () => {
  const { navigator, nativeCalls } = frontend('confirm', { real: true });
  const options = requestOptions('create');
  options.publicKey.pubKeyCredParams = [{ type: 'public-key', alg: -35 }];
  await assert.rejects(navigator.credentials.create(options), (error) => {
    assert.ok(error instanceof DOMException);
    assert.equal(error.name, 'NotSupportedError');
    return true;
  });
  assert.equal(nativeCalls.length, 0);
});

// Pages and libraries serialise credentials with toJSON() or JSON.stringify()
// before posting them to their server (WebAuthn Level 3,
// PublicKeyCredential.toJSON()). Like the browser's, the result must follow
// the credential's current buffers, not the bytes it was created with.
function assertFollowsBuffer(credential, expected) {
  const clientData = new Uint8Array(credential.response.clientDataJSON);
  clientData[0] ^= 1;
  const changed = b64(clientData);
  assert.notEqual(changed, expected.response.clientDataJSON);
  assert.equal(credential.toJSON().response.clientDataJSON, changed);
  assert.equal(JSON.parse(JSON.stringify(credential)).response.clientDataJSON, changed);
}
test('a created credential serialises to RegistrationResponseJSON', { timeout: 2000 }, async () => {
  const { navigator } = frontend('confirm');
  const credential = await navigator.credentials.create(requestOptions('create'));
  const expected = {
    id: b64(RAW_ID),
    rawId: b64(RAW_ID),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: { credProps: { rk: true } },
    response: {
      clientDataJSON: b64(CLIENT_DATA),
      attestationObject: b64(ATTESTATION_OBJECT),
      authenticatorData: b64(AUTHENTICATOR_DATA),
      transports: ['internal', 'hybrid'],
      publicKey: b64(PUBLIC_KEY_DER),
      publicKeyAlgorithm: -7,
    },
  };
  assert.deepEqual(JSON.parse(JSON.stringify(credential.toJSON())), expected);
  assert.deepEqual(JSON.parse(JSON.stringify(credential)), expected);
  assertFollowsBuffer(credential, expected);
});

test('an assertion serialises to AuthenticationResponseJSON', { timeout: 2000 }, async () => {
  const { navigator } = frontend('confirm');
  const credential = await navigator.credentials.get(requestOptions('get'));
  const expected = {
    id: b64(RAW_ID),
    rawId: b64(RAW_ID),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    // Matches getClientExtensionResults(), which reports credProps for both operations.
    clientExtensionResults: { credProps: { rk: true } },
    response: {
      clientDataJSON: b64(CLIENT_DATA),
      authenticatorData: b64(AUTHENTICATOR_DATA),
      signature: b64(SIGNATURE),
      userHandle: b64(USER_HANDLE),
    },
  };
  assert.deepEqual(JSON.parse(JSON.stringify(credential.toJSON())), expected);
  assert.deepEqual(JSON.parse(JSON.stringify(credential)), expected);
  assertFollowsBuffer(credential, expected);
});

test('an assertion exposes the sign-in data the page reads', { timeout: 2000 }, async () => {
  const { navigator, nativeCalls, listeners } = frontend('confirm');
  const listenersBefore = listeners.size;
  const credential = await navigator.credentials.get(requestOptions('get'));

  assert.equal(nativeCalls.length, 0);
  assert.equal(listeners.size, listenersBefore, 'the response listener is removed');
  assert.ok(credential instanceof PublicKeyCredential);
  assert.equal(credential.type, 'public-key');
  assert.equal(credential.id, b64(RAW_ID));
  assert.deepEqual(bytesOf(credential.rawId), RAW_ID);
  assert.equal(credential.authenticatorAttachment, 'platform');

  const { response } = credential;
  assert.ok(response instanceof AuthenticatorAssertionResponse);
  assert.deepEqual(bytesOf(response.clientDataJSON), CLIENT_DATA);
  assert.deepEqual(bytesOf(response.authenticatorData), AUTHENTICATOR_DATA);
  assert.deepEqual(bytesOf(response.signature), SIGNATURE);
  assert.deepEqual(bytesOf(response.userHandle), USER_HANDLE);
});
