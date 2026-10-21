import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

import { createIndexedDB } from './helpers/indexedDB.mjs';

const require = createRequire(import.meta.url);
const base64url = require('../.test-build/utils/base64url.js');

// Sealed like store.ts: HKDF, then AES-GCM
async function envelope(rootKey, info, payload) {
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    rootKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(payload)));
  return { iv: base64url.base64UrlEncode(iv), data: base64url.base64UrlEncode(new Uint8Array(data)) };
}

// Real store on an in-memory NydiaDB
async function vault(rpIds, { root = true, corrupt = false } = {}) {
  const rootKey = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'HKDF', false, ['deriveKey']);
  const passkeys = new Map();
  for (const [index, rpId] of rpIds.entries()) {
    const uniqueId = `passkey-${index}`;
    passkeys.set(uniqueId, {
      uniqueId,
      metadata: await envelope(rootKey, 'metadata:v1', { rpId, userName: 'user', creationTime: index }),
      secret: await envelope(rootKey, 'secret:v1', {}),
      isSynced: false,
    });
  }
  if (corrupt) passkeys.get('passkey-0').metadata.data = base64url.base64UrlEncode(new Uint8Array(32));

  const indexedDB = createIndexedDB();
  indexedDB.databases.set('NydiaDB', {
    version: 4,
    stores: new Map([
      ['passkeys', { keyPath: 'uniqueId', data: passkeys }],
      ['settings', { keyPath: 'id', data: new Map(root ? [['rootKey', { id: 'rootKey', key: rootKey }]] : []) }],
    ]),
  });
  const context = {
    exports: {}, Error, DOMException, Uint8Array, ArrayBuffer, TextEncoder, TextDecoder, atob, btoa, JSON,
    indexedDB, crypto,
    require(name) {
      const imports = {
        './logger': { logDebug() {}, logInfo() {}, logWarn() {}, logError() {} },
        './utils/base64url': base64url,
      };
      assert.ok(name in imports, `Unexpected import: ${name}`);
      return imports[name];
    },
  };
  runInNewContext(readFileSync(new URL('../.test-build/store.js', import.meta.url), 'utf8'), context);
  return context.exports;
}

test('store: getAllRpIds lists each site of the vault once', async () => {
  const store = await vault(['github.com', 'github.com', 'user1.github.com', 'example.com']);
  assert.deepEqual([...await store.getAllRpIds()].sort(), ['example.com', 'github.com', 'user1.github.com']);
  assert.equal((await (await vault([])).getAllRpIds()).size, 0);
});

test('store: getAllRpIds refuses a partial list', async () => {
  const store = await vault(['github.com', 'example.com'], { corrupt: true });
  assert.equal(await store.getAllRpIds(), null);
  assert.equal((await store.getAllCredentialsMetadata()).length, 1);
});

test('store: getAllRpIds needs the root key', async () => {
  assert.equal(await (await vault(['github.com'], { root: false })).getAllRpIds(), null);
});
