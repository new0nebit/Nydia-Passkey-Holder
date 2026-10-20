import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';

const ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a6xkAAAAASUVORK5CYII=';
const imageBytes = Uint8Array.from(atob(ICON.split(',')[1]), (character) => character.charCodeAt(0));

function load(name, imports = {}, globals = {}) {
  const context = {
    exports: {}, URL, DOMException, Error, Response, Blob, Uint8Array,
    AbortController, atob, btoa, setTimeout, clearTimeout,
    require(name) {
      assert.ok(name in imports, `Unexpected import: ${name}`);
      return imports[name];
    },
    ...globals,
  };
  runInNewContext(readFileSync(new URL(`../.test-build/siteIcons/${name}.js`, import.meta.url), 'utf8'), context);
  return context.exports;
}
const images = load('image');
const require = createRequire(import.meta.url);
const rpId = require('../.test-build/utils/rpId.js');
const menuSender = { url: 'chrome-extension://audit/menu.html' };
const pageSender = { origin: 'https://login.example.com', frameId: 0, tab: {} };

function background(enabled = false) {
  const calls = [];
  const cache = new Map();
  const feature = load('background', {
    'browser-api': { runtime: { getURL: (name) => `chrome-extension://audit/${name}` } },
    '../utils/rpId': rpId,
    './image': images,
    './storage': {
      async iconsEnabled() { calls.push('enabled'); return enabled; },
      async setIconsEnabled(value) { calls.push(['set', value]); enabled = value; },
      async readIcon(rpId) { calls.push(['read', rpId]); return cache.get(rpId) ?? null; },
      async writeIcon(rpId, dataUrl) { calls.push(['write', rpId, dataUrl]); cache.set(rpId, dataUrl); return true; },
    },
  });
  return { request: feature.handleSiteIconMessage, calls, cache };
}

test('website icons: disabled state never reads or writes the icon cache', async () => {
  const icons = background();
  assert.equal((await icons.request({ type: 'getSiteIcon', rpId: 'example.com' }, pageSender)).enabled, false);
  assert.equal((await icons.request({ type: 'saveSiteIcon', rpId: 'example.com', dataUrl: ICON }, pageSender)).enabled, false);
  assert.deepEqual(icons.calls, ['enabled', 'enabled']);
});

test('website icons: only the menu changes the preference, without Sia settings', async () => {
  const icons = background();
  for (const sender of [pageSender, { url: 'chrome-extension://audit.evil/menu.html' }, { url: 'https://audit/menu.html' }]) {
    await assert.rejects(icons.request({ type: 'setSiteIconsEnabled', enabled: true }, sender), { name: 'SecurityError' });
  }
  assert.deepEqual(icons.calls, []);
  assert.equal((await icons.request({ type: 'setSiteIconsEnabled', enabled: true }, menuSender)).enabled, true);
  assert.equal((await icons.request({ type: 'getSiteIcon' }, menuSender)).enabled, true);
  await assert.rejects(icons.request({ type: 'setSiteIconsEnabled', enabled: 'true' }, menuSender));
  assert.equal((await icons.request({ type: 'setSiteIconsEnabled', enabled: false }, menuSender)).enabled, false);
});

test('website icons: page callers cannot read or overwrite another RP', async () => {
  const icons = background(true);
  for (const type of ['getSiteIcon', 'saveSiteIcon']) {
    await assert.rejects(icons.request({ type, rpId: 'bank.example', dataUrl: ICON }, pageSender), { name: 'SecurityError' });
    await assert.rejects(icons.request({ type, rpId: 'example.com', dataUrl: ICON }, {}), { name: 'SecurityError' });
  }
  assert.deepEqual(icons.calls, []);
  await icons.request({ type: 'saveSiteIcon', rpId: 'EXAMPLE.COM', dataUrl: ICON }, pageSender);
  assert.equal((await icons.request({ type: 'getSiteIcon', rpId: 'example.com' }, pageSender)).dataUrl, ICON);
  assert.deepEqual([...icons.cache.keys()], ['example.com']);
});

test('website icons: invalid and oversized images are never stored', async () => {
  const icons = background(true);
  for (const dataUrl of ['https://tracker.example/icon.png', 'data:text/html;base64,YQ==', 'data:image/png;base64,',
    'data:image/png;base64,' + btoa('a'.repeat(65537))]) {
    await assert.rejects(icons.request({ type: 'saveSiteIcon', rpId: 'example.com', dataUrl }, pageSender));
  }
  assert.equal(icons.cache.size, 0);
  assert.equal(icons.calls.some((call) => Array.isArray(call) && call[0] === 'write'), false);
});

function pageIcons({ enabled, stored = null, cached = null }) {
  const messages = [];
  let cacheReads = 0;
  let networkCalls = 0;
  const client = load('client', {
    'browser-api': { runtime: { async sendMessage(message) {
      messages.push(structuredClone(message));
      return message.type === 'getSiteIcon' ? { enabled, dataUrl: stored } : { enabled, saved: true };
    } } },
    '../popup/pageIcon': { async readCachedPageIcon() { cacheReads++; return cached; } },
    './image': images,
  }, { async fetch() { networkCalls++; return new Response(imageBytes, { headers: { 'content-type': 'image/png' } }); } });
  return { read: client.getPageSiteIcon, messages, get cacheReads() { return cacheReads; }, get networkCalls() { return networkCalls; } };
}

test('authentication icons: disabled preference skips even the browser cache', async () => {
  const icons = pageIcons({ enabled: false, stored: ICON, cached: ICON });
  assert.equal(await icons.read('example.com'), undefined);
  assert.equal(icons.cacheReads, 0);
  assert.equal(icons.networkCalls, 0);
  assert.equal(icons.messages.length, 1);
});

test('authentication icons: a page-cache image is saved locally without a network request', async () => {
  const icons = pageIcons({ enabled: true, cached: ICON });
  assert.equal(await icons.read('example.com'), ICON);
  assert.deepEqual(icons.messages[1], { type: 'saveSiteIcon', rpId: 'example.com', dataUrl: ICON });
  assert.equal(icons.networkCalls, 0);
});

test('authentication icons: local storage survives a page-cache miss, with no Google fallback', async () => {
  for (const stored of [ICON, null]) {
    const icons = pageIcons({ enabled: true, stored });
    assert.equal(await icons.read('example.com'), stored ?? undefined);
    assert.equal(icons.cacheReads, 1);
    assert.equal(icons.networkCalls, 0);
    assert.equal(icons.messages.length, 1);
  }
});

function menuIcons({ enabled = true, stored = null, response, domain = (name) => name } = {}) {
  const requests = [];
  const saved = [];
  const feature = load('menu', {
    './client': {
      async getSiteIcon(rpId) { return { enabled, dataUrl: stored, iconDomain: domain(rpId) }; },
      async saveSiteIcon(rpId, dataUrl) { saved.push({ rpId, dataUrl }); stored = dataUrl; return enabled; },
    },
    './image': images,
  }, { async fetch(url, options) {
    requests.push({ url, options });
    return response ? response(options) : new Response(imageBytes, { headers: { 'content-type': 'image/png' } });
  } });
  return { ...feature, requests, saved };
}

test('menu icons: disabled or locally cached icons never contact Google', async () => {
  for (const state of [{ enabled: false, stored: ICON }, { enabled: true, stored: ICON }]) {
    const icons = menuIcons(state);
    assert.equal(await icons.loadMenuSiteIcon('example.com'), state.enabled ? ICON : null);
    assert.equal(icons.requests.length, 0);
    assert.equal(icons.saved.length, 0);
  }
});

test('menu icons: download a missing icon once per RP and persist it for later renders', async () => {
  const icons = menuIcons({ domain: rpId.iconDomain });
  const results = await Promise.all([icons.loadMenuSiteIcon('login.sia.storage'), icons.loadMenuSiteIcon('login.sia.storage')]);
  assert.deepEqual(results, [ICON, ICON]);
  assert.equal(icons.requests.length, 1);
  assert.equal(icons.requests[0].url, 'https://www.google.com/s2/favicons?domain=sia.storage&sz=64');
  assert.equal(icons.requests[0].options.credentials, 'omit');
  assert.equal(icons.requests[0].options.referrerPolicy, 'no-referrer');
  assert.deepEqual(icons.saved, [{ rpId: 'login.sia.storage', dataUrl: ICON }]);
  assert.equal(await icons.loadMenuSiteIcon('login.sia.storage'), ICON);
  assert.equal(icons.requests.length, 1);
});

test('menu icons: special and local names never contact Google', async () => {
  for (const name of ['localhost', 'nas.local', 'nas.home.arpa', 'shop.abcd.onion', 'router.lan']) {
    const icons = menuIcons({ domain: rpId.iconDomain });
    assert.equal(await icons.loadMenuSiteIcon(name), null);
    assert.equal(icons.requests.length, 0);
  }
});

test('menu icons: failed, non-image, empty and oversized downloads keep the globe', async () => {
  for (const response of [
    () => new Response(imageBytes, { status: 404, headers: { 'content-type': 'image/png' } }),
    () => new Response(imageBytes, { headers: { 'content-type': 'text/html' } }),
    () => new Response('', { headers: { 'content-type': 'image/png' } }),
    () => new Response(new Uint8Array(65537), { headers: { 'content-type': 'image/png' } }),
  ]) {
    const icons = menuIcons({ response });
    assert.equal(await icons.loadMenuSiteIcon('example.com'), null);
    assert.equal(icons.saved.length, 0);
  }
});

test('menu icons: disabling cancels a pending download and prevents its save', async () => {
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  let aborted = false;
  const icons = menuIcons({ response: ({ signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => { aborted = true; reject(new Error('Aborted')); }, { once: true });
    started();
  }) });
  const result = icons.loadMenuSiteIcon('example.com');
  await ready;
  icons.cancelMenuIconLoads();
  assert.equal(await result, null);
  assert.equal(aborted, true);
  assert.equal(icons.saved.length, 0);
  const waiting = menuIcons();
  const queued = waiting.loadMenuSiteIcon('example.com');
  waiting.cancelMenuIconLoads();
  assert.equal(await queued, null);
  assert.equal(waiting.requests.length, 0);
});

test('website icons: only recognised image formats count as icons', () => {
  const dataUrl = (type, bytes) => `data:${type};base64,${btoa(bytes)}`;
  for (const [type, bytes] of [
    ['image/png', atob(ICON.split(',')[1])],
    ['image/jpeg', '\xff\xd8\xff\xe0rest'],
    ['image/gif', 'GIF89a rest'],
    ['image/x-icon', '\x00\x00\x01\x00rest'],
    ['image/vnd.microsoft.icon', '\x00\x00\x01\x00rest'],
    ['image/webp', 'RIFF\x00\x00\x00\x00WEBPrest'],
    ['image/avif', '\x00\x00\x00\x1cftypavifrest'],
    ['image/svg+xml', '<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"></svg>'],
    ['image/png', '\x89PNG\r\n\x1a\nrest'],
  ]) {
    assert.equal(images.isSiteIcon(dataUrl(type, bytes)), true, type);
  }
  for (const [type, bytes] of [
    ['image/png', 'not an image'],
    ['image/png', '<html>Not found</html>'],
    ['image/png', '<svg xmlns="http://www.w3.org/2000/svg"></svg>'],
    ['image/svg+xml', '<html><body>Not found</body></html>'],
  ]) {
    assert.equal(images.isSiteIcon(dataUrl(type, bytes)), false, `${type}: ${bytes}`);
  }
});

test('authentication icons: a stalled lookup cannot hold up the confirmation window', async () => {
  const client = load('client', {
    'browser-api': { runtime: { sendMessage: () => new Promise(() => {}) } },
    '../popup/pageIcon': { async readCachedPageIcon() { return null; } },
    './image': images,
  }, {
    setTimeout(callback, ms) {
      assert.equal(ms, 500);
      queueMicrotask(callback);
      return 0;
    },
    clearTimeout() {},
  });
  assert.equal(await client.getPageSiteIcon('example.com'), undefined);
});

test('website icons: the menu learns which domain to ask Google for', async () => {
  const icons = background(true);
  for (const [name, domain] of [['login.sia.storage', 'sia.storage'], ['localhost', null], ['abcd.onion', null]]) {
    assert.equal((await icons.request({ type: 'getSiteIcon', rpId: name }, menuSender)).iconDomain, domain);
  }
});

test('menu icons: the client passes on only a domain name', async () => {
  for (const [iconDomain, expected] of [['sia.storage', 'sia.storage'], [42, null], [undefined, null]]) {
    const client = load('client', {
      'browser-api': { runtime: { async sendMessage() { return { enabled: true, iconDomain }; } } },
      '../popup/pageIcon': { async readCachedPageIcon() { return null; } },
      './image': images,
    });
    assert.equal((await client.getSiteIcon('login.sia.storage')).iconDomain, expected);
  }
});
