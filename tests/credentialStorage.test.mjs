import assert from 'node:assert/strict';
import { test } from 'node:test';
import { settingsVault } from './helpers/settingsVault.mjs';

// Chromium rejects an explicitly undefined optional BufferSource, while Node
// accepts it. Keep that browser constraint in the regular test suite too.
const strictCrypto = {
  getRandomValues: crypto.getRandomValues.bind(crypto),
  subtle: new Proxy(crypto.subtle, {
    get(target, method) {
      if (method === 'encrypt' || method === 'decrypt') return (params, ...args) => {
        if ('additionalData' in params && params.additionalData === undefined) {
          throw new TypeError('additionalData: Not a BufferSource');
        }
        return target[method](params, ...args);
      };
      return target[method].bind(target);
    },
  }),
};
const encode = bytes => Buffer.from(bytes).toString('base64url');

async function legacyEnvelope(root, info, payload) {
  const key = await crypto.subtle.deriveKey({
    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info),
  }, root, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(payload)));
  return { iv: encode(iv), data: encode(data) };
}

async function checkSigning(secret, publicKey) {
  const key = await crypto.subtle.importKey('pkcs8', Buffer.from(secret.privateKey, 'base64url'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, challenge);
  assert.equal(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, challenge), true);
}

test('credential storage: new passkeys encrypt, decrypt and sign with browser-strict Web Crypto', async () => {
  const { store, reload } = await settingsVault(undefined, { crypto: strictCrypto });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const id = await store.savePrivateKey(new Uint8Array([1, 2, 3]), 'example.com', pair.privateKey, new Uint8Array([4]), -7, 'User');
  const reopened = reload();
  assert.equal((await reopened.getAllCredentialsMetadata())[0].rpId, 'example.com');
  const secret = await reopened.openSecret(id);
  assert.equal(secret.credentialId, 'AQID');
  await checkSigning(secret, pair.publicKey);
});

test('credential storage: pre-encryption-change passkeys remain readable without rewriting their envelopes', async () => {
  const { store, rootKey, indexedDB } = await settingsVault(undefined, { crypto: strictCrypto });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const secret = { credentialId: 'AQID', userHandle: 'BA', publicKeyAlgorithm: -7, privateKey: encode(await crypto.subtle.exportKey('pkcs8', pair.privateKey)) };
  const record = {
    uniqueId: 'legacy-passkey', isSynced: true,
    metadata: await legacyEnvelope(rootKey, 'metadata:v1', { rpId: 'example.com', userName: 'Legacy', creationTime: 1 }),
    secret: await legacyEnvelope(rootKey, 'secret:v1', secret),
  };
  indexedDB.entries('NydiaDB', 'passkeys').set(record.uniqueId, structuredClone(record));
  assert.equal((await store.getAllCredentialsMetadata())[0].userName, 'Legacy');
  const opened = await store.openSecret(record.uniqueId);
  assert.deepEqual(opened, secret);
  await checkSigning(opened, pair.publicKey);
  assert.deepEqual(indexedDB.entries('NydiaDB', 'passkeys').get(record.uniqueId), record);
});

test('renterd settings still authenticate their additional data with browser-strict Web Crypto', async () => {
  const { store, saved } = await settingsVault(undefined, { crypto: strictCrypto });
  const settings = { serverAddress: 'localhost', serverPort: 9980, password: 'test-only', bucketName: 'test' };
  assert.equal((await store.handleMessageInBackground({ type: 'saveSettings', settings })).status, 'ok');
  // saved() decrypts independently using the expected renterd-specific AAD.
  assert.deepEqual(await saved(), settings);
});
