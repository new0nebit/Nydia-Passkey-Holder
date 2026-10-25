import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';

import { createIndexedDB } from './indexedDB.mjs';

const require = createRequire(import.meta.url);
const base64url = require('../../.test-build/utils/base64url.js');
const logger = { logDebug() {}, logError() {} };

// Real Web Crypto and store.ts, with only IndexedDB replaced. reload() starts
// another store context against the same persisted data, without its key cache.
export async function settingsVault(stored, { plaintext = false, root = true, crypto: storeCrypto = crypto } = {}) {
  const rootKey = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('renterd-settings:v1') },
    rootKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  const seal = async (payload) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key,
      new TextEncoder().encode(JSON.stringify(payload)));
    return { id: 'renterdSettings', version: 1, iv: base64url.base64UrlEncode(iv), data: base64url.base64UrlEncode(data) };
  };
  const indexedDB = createIndexedDB();
  const settings = new Map(root ? [['rootKey', { id: 'rootKey', key: rootKey }]] : []);
  if (stored) settings.set('renterdSettings', plaintext ? { ...stored, id: 'renterdSettings' } : await seal(stored));
  indexedDB.databases.set('NydiaDB', {
    version: 4,
    stores: new Map([
      ['passkeys', { keyPath: 'uniqueId', data: new Map() }],
      ['settings', { keyPath: 'id', data: settings }],
    ]),
  });
  const reload = () => {
    const context = {
      exports: {}, crypto: storeCrypto, indexedDB, Error, DOMException,
      Uint8Array, ArrayBuffer, TextEncoder, TextDecoder, atob, btoa, JSON,
      require(name) {
        const imports = { './logger': logger, './utils/base64url': base64url };
        assert.ok(name in imports, `Unexpected import: ${name}`);
        return imports[name];
      },
    };
    runInNewContext(readFileSync(new URL('../../.test-build/store.js', import.meta.url), 'utf8'), context);
    return context.exports;
  };
  const record = () => settings.get('renterdSettings');
  const saved = async () => {
    const { iv, data } = record();
    const opened = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64url.base64UrlDecode(iv) },
      key, base64url.base64UrlDecode(data));
    return JSON.parse(new TextDecoder().decode(opened));
  };
  return { store: reload(), reload, record, saved, seal, settings, indexedDB, rootKey, database: indexedDB.databases.get('NydiaDB') };
}

// Pause the first crypto operation to interleave a competing save.
export function holdingCrypto(method) {
  let release;
  let reach;
  const reached = new Promise((resolve) => { reach = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const subtle = {};
  for (const name of ['deriveKey', 'encrypt', 'decrypt']) subtle[name] = crypto.subtle[name].bind(crypto.subtle);
  let held = false;
  subtle[method] = async (...args) => {
    if (!held) { held = true; reach(); await gate; }
    return crypto.subtle[method](...args);
  };
  return { crypto: { subtle, getRandomValues: crypto.getRandomValues.bind(crypto) }, reached, release };
}
