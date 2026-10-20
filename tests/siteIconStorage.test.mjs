import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

import { createIndexedDB } from './helpers/indexedDB.mjs';

const ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a6xkAAAAASUVORK5CYII=';
const DAY = 24 * 60 * 60 * 1000;
const require = createRequire(import.meta.url);
const base64url = require('../.test-build/utils/base64url.js');

function load(name, imports, globals = {}) {
  const context = {
    exports: {}, Error, DOMException, Uint8Array, ArrayBuffer, TextEncoder, TextDecoder, atob, btoa,
    require(name) {
      assert.ok(name in imports, `Unexpected import: ${name}`);
      return imports[name];
    },
    ...globals,
  };
  runInNewContext(readFileSync(new URL(`../.test-build/siteIcons/${name}.js`, import.meta.url), 'utf8'), context);
  return context.exports;
}
const images = load('image', {});

// Real storage on an in-memory IndexedDB
// beforeEncrypt interleaves other writes
async function storage({ root = true, now = () => Date.now(), beforeEncrypt } = {}) {
  const indexedDB = createIndexedDB();
  const rootKey = root
    ? await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'HKDF', false, ['deriveKey'])
    : null;
  const subtle = {
    deriveKey: (...args) => crypto.subtle.deriveKey(...args),
    sign: (...args) => crypto.subtle.sign(...args),
    decrypt: (...args) => crypto.subtle.decrypt(...args),
    async encrypt(params, key, data) {
      await beforeEncrypt?.(new TextDecoder().decode(data));
      return crypto.subtle.encrypt(params, key, data);
    },
  };
  const feature = load('storage', {
    '../store': { async getRootKeyIfAvailable() { return rootKey; } },
    '../utils/base64url': base64url,
    './image': images,
  }, {
    indexedDB,
    crypto: { subtle, getRandomValues: (array) => crypto.getRandomValues(array) },
    Date: { now },
  });
  return { ...feature, records: () => indexedDB.entries('NydiaSiteIcons', 'icons') };
}

test('icon storage: icons and misses are encrypted under an HMAC of the RP ID', async () => {
  const icons = await storage();
  assert.equal(await icons.writeIcon('example.com', ICON), true);
  assert.equal(await icons.markIconMissing('no-icon.example'), true);
  assert.equal((await icons.readIcon('example.com')).dataUrl, ICON);
  assert.ok(Date.now() - (await icons.readIcon('no-icon.example')).missingSince < 1000);
  assert.equal(await icons.readIcon('other.example'), null);

  const records = [...icons.records()];
  assert.equal(records.length, 2);
  for (const [id, record] of records) {
    assert.match(id, /^[A-Za-z0-9_-]{43}$/);
    const raw = new TextDecoder().decode(record.data);
    for (const plaintext of ['example', 'iVBOR', 'missing']) assert.equal(raw.includes(plaintext), false);
  }
});

test('icon storage: a miss never replaces a saved icon', async () => {
  const icons = await storage();
  await icons.writeIcon('example.com', ICON);
  assert.equal(await icons.markIconMissing('example.com'), false);
  assert.equal((await icons.readIcon('example.com')).dataUrl, ICON);
});

test('icon storage: an icon saved while a miss is being recorded wins', async () => {
  let icons;
  icons = await storage({
    async beforeEncrypt(plaintext) {
      if (plaintext.startsWith('missing:')) await icons.writeIcon('example.com', ICON);
    },
  });
  assert.equal(await icons.markIconMissing('example.com'), false);
  assert.equal((await icons.readIcon('example.com')).dataUrl, ICON);
  assert.equal(icons.records().size, 1);
});

test('icon storage: a repeated miss refreshes its date', async () => {
  let time = 1_000;
  const icons = await storage({ now: () => time });
  assert.equal(await icons.markIconMissing('example.com'), true);
  time += 31 * DAY;
  assert.equal(await icons.markIconMissing('example.com'), true);
  assert.equal((await icons.readIcon('example.com')).missingSince, time);
});

test('icon storage: nothing is read or written without a root key', async () => {
  const icons = await storage({ root: false });
  assert.equal(await icons.writeIcon('example.com', ICON), false);
  assert.equal(await icons.markIconMissing('example.com'), false);
  assert.equal(await icons.readIcon('example.com'), null);
  assert.equal(icons.records().size, 0);
});
