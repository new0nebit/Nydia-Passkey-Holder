import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../.test-build/popup/pageIcon.js', import.meta.url), 'utf8');
const images = createRequire(import.meta.url)('../.test-build/siteIcons/image.js');
const PNG = Uint8Array.from(atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a6xkAAAAASUVORK5CYII='), (character) => character.charCodeAt(0));
const PNG_URL = `data:image/png;base64,${btoa(String.fromCharCode(...PNG))}`;
function loadIconReader({ candidates = [], fetchResponse, timeout = setTimeout } = {}) {
  const calls = [];
  const context = {
    exports: {}, URL, Blob, Promise,
    require(name) { return name === '../siteIcons/image' ? images : { logDebug() {} }; },
    window: { location: { origin: 'https://example.com' } },
    document: { querySelectorAll() { return candidates.map((href) => ({ href })); } },
    setTimeout: timeout,
    async fetch(url, options) {
      calls.push({ url, options: { ...options } });
      return fetchResponse(url);
    },
  };
  runInNewContext(source, context);
  return { read: context.exports.readCachedPageIcon, calls };
}
function cachedImage(bytes = PNG) {
  return { ok: true, headers: new Headers({ 'content-type': 'image/png' }), async blob() { return new Blob([bytes], { type: 'image/png' }); } };
}
const SAFE_OPTIONS = { cache: 'only-if-cached', mode: 'same-origin', credentials: 'omit', redirect: 'error' };

test('page icon skips other origins and only reads the local cache', async () => {
  const icon = loadIconReader({
    candidates: ['https://tracker.example/icon.png', 'https://example.com/icon.png'],
    fetchResponse: async () => cachedImage(),
  });
  assert.equal(await icon.read(), PNG_URL);
  assert.deepEqual(icon.calls, [{ url: 'https://example.com/icon.png', options: SAFE_OPTIONS }]);
});

test('a cached response that is not a real image falls through to the next candidate', async () => {
  const icon = loadIconReader({
    candidates: ['https://example.com/broken.png'],
    fetchResponse: async (url) => cachedImage(url.endsWith('broken.png') ? new TextEncoder().encode('not an image') : PNG),
  });
  assert.equal(await icon.read(), PNG_URL);
  assert.deepEqual(icon.calls.map((call) => call.url), ['https://example.com/broken.png', 'https://example.com/favicon.ico']);
});

test('a cache miss keeps the fallback icon without retrying in a network-enabled mode', async () => {
  const icon = loadIconReader({
    candidates: ['https://example.com/icon.png', 'https://example.com/icon.png'],
    fetchResponse: async () => { throw new TypeError('Cache miss'); },
  });
  assert.equal(await icon.read(), null);
  assert.deepEqual(icon.calls.map((call) => call.url), ['https://example.com/icon.png', 'https://example.com/favicon.ico']);
  for (const { options } of icon.calls) assert.deepEqual(options, SAFE_OPTIONS);
});

test('invalid, empty and oversized cached responses are not sent to the popup', async () => {
  const icon = loadIconReader({
    candidates: ['https://example.com/text', 'https://example.com/empty', 'https://example.com/large'],
    fetchResponse: async (url) => ({
      ok: !url.endsWith('favicon.ico'),
      headers: new Headers({ 'content-type': url.endsWith('/text') ? 'text/html' : 'image/png' }),
      async blob() { return new Blob([url.endsWith('/large') ? new Uint8Array(65537) : '']); },
    }),
  });
  assert.equal(await icon.read(), null);
});

// Each refusal holds on its own
test('a failed response is refused even with a body within the size limit', async () => {
  const icon = loadIconReader({ fetchResponse: async () => ({ ...cachedImage(), ok: false }) });
  assert.equal(await icon.read(), null);
});

test('a response that is not an image is refused even with a body of allowed size', async () => {
  const icon = loadIconReader({
    fetchResponse: async () => ({ ...cachedImage(), headers: new Headers({ 'content-type': 'text/html' }) }),
  });
  assert.equal(await icon.read(), null);
});

test('an unresponsive cache read cannot hold up the confirmation window', async () => {
  const icon = loadIconReader({
    fetchResponse: () => new Promise(() => {}),
    timeout(callback, ms) {
      assert.equal(ms, 300);
      queueMicrotask(callback);
    },
  });
  assert.equal(await icon.read(), null);
});
