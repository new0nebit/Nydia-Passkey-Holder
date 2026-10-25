import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

import { createIndexedDB } from './helpers/indexedDB.mjs';

const require = createRequire(import.meta.url);
const base64url = require('../.test-build/utils/base64url.js');

// Real store on an empty in-memory NydiaDB
function emptyStore() {
  const indexedDB = createIndexedDB();
  indexedDB.databases.set('NydiaDB', {
    version: 4,
    stores: new Map([
      ['passkeys', { keyPath: 'uniqueId', data: new Map() }],
      ['settings', { keyPath: 'id', data: new Map() }],
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
  return { store: context.exports, database: indexedDB.databases.get('NydiaDB') };
}

test('the root key is reported saved only once committed, and a failed commit keeps no key', async () => {
  const { store, database } = emptyStore();
  const key = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'HKDF', false, ['deriveKey']);

  database.failCommit = true;
  await assert.rejects(store.setRootKey(key), /Commit failed/);
  assert.equal(await store.getRootKeyIfAvailable(), null);
  assert.equal(database.stores.get('settings').data.has('rootKey'), false);

  database.failCommit = false;
  await store.setRootKey(key);
  assert.equal(await store.getRootKeyIfAvailable(), key);
});
