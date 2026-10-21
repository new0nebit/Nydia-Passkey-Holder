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

function background(enabled = false, { prune } = {}) {
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
      async writeIcon(rpId, dataUrl) { calls.push(['write', rpId, dataUrl]); cache.set(rpId, { dataUrl }); return true; },
      async markIconMissing(rpId) { calls.push(['missing', rpId]); cache.set(rpId, { missingSince: Date.now() }); return true; },
      async pruneIcons() { calls.push('prune'); await prune?.(); },
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

function menuIcons({ enabled = true, stored = null, missing = false, response, domain = (name) => name } = {}, globals = {}) {
  const requests = [];
  const saved = [];
  const missed = [];
  const feature = load('menu', {
    './client': {
      async getSiteIcon(rpId) {
        const icon = saved.findLast((entry) => entry.rpId === rpId)?.dataUrl ?? stored;
        return { enabled, dataUrl: icon, missing: missing || missed.includes(rpId), iconDomain: domain(rpId) };
      },
      async saveSiteIcon(rpId, dataUrl) { saved.push({ rpId, dataUrl }); return enabled; },
      async markSiteIconMissing(rpId) { missed.push(rpId); },
    },
    './image': images,
  }, { async fetch(url, options) {
    requests.push({ url, options });
    return response ? response(options) : new Response(imageBytes, { headers: { 'content-type': 'image/png' } });
  }, ...globals });
  return { ...feature, requests, saved, missed };
}

const image = () => new Response(imageBytes, { headers: { 'content-type': 'image/png' } });

// Released by the test, oldest first
function heldDownloads() {
  const releases = [];
  return {
    response: () => new Promise((resolve) => releases.push(() => resolve(image()))),
    release: () => releases.shift()(),
    get held() { return releases.length; },
  };
}

async function ticks(count = 10) {
  for (let index = 0; index < count; index++) await new Promise((resolve) => setTimeout(resolve, 1));
}

async function until(condition) {
  for (let index = 0; index < 200 && !condition(); index++) await ticks(1);
  assert.ok(condition());
}

const requested = (icons, rpId) => icons.requests.some(({ url }) => url.includes(`domain=${rpId}&`));

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

test('menu icons: subdomains of one site keep separate icons and misses', async () => {
  const icons = menuIcons({ domain: rpId.iconDomain, response: () => icons.requests.length === 1
    ? new Response(imageBytes, { status: 404, headers: { 'content-type': 'image/png' } })
    : image() });
  assert.equal(await icons.loadMenuSiteIcon('login.sia.storage'), null);
  assert.equal(await icons.loadMenuSiteIcon('app.sia.storage'), ICON);
  assert.deepEqual(icons.requests.map(({ url }) => url), Array(2).fill('https://www.google.com/s2/favicons?domain=sia.storage&sz=64'));
  assert.deepEqual(icons.missed, ['login.sia.storage']);
  assert.deepEqual(icons.saved, [{ rpId: 'app.sia.storage', dataUrl: ICON }]);
});

test('menu icons: special and local names never contact Google', async () => {
  for (const name of ['localhost', 'nas.local', 'nas.home.arpa', 'shop.abcd.onion', 'router.lan']) {
    const icons = menuIcons({ domain: rpId.iconDomain });
    assert.equal(await icons.loadMenuSiteIcon(name), null);
    assert.equal(icons.requests.length, 0);
    assert.deepEqual(icons.missed, []);
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

test('website icons: reading stops at the size limit', async () => {
  let pulls = 0;
  let cancellations = 0;
  // 8 MiB in 16 KiB chunks
  const large = () => new ReadableStream({
    pull(controller) {
      if (++pulls > 512) controller.close();
      else controller.enqueue(new Uint8Array(16 * 1024));
    },
    cancel() { cancellations++; },
  }, { highWaterMark: 0 });
  assert.equal(await images.imageDataUrl(new Response(large(), { headers: { 'content-type': 'image/png' } })), null);
  assert.equal(pulls, 5);
  assert.equal(cancellations, 1);

  pulls = 0;
  cancellations = 0;
  const declared = new Response(large(), { headers: { 'content-type': 'image/png', 'content-length': '8388608' } });
  assert.equal(await images.imageDataUrl(declared), null);
  assert.equal(pulls, 0);
  assert.equal(cancellations, 1);
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

test('website icons: a Google miss is reported for 30 days, then retried', async () => {
  const icons = background(true);
  const day = 24 * 60 * 60 * 1000;
  for (const [missingSince, missing] of [[Date.now() - 29 * day, true], [Date.now() - 31 * day, false], [Date.now() + day, false]]) {
    icons.cache.set('example.com', { missingSince });
    const state = await icons.request({ type: 'getSiteIcon', rpId: 'example.com' }, menuSender);
    assert.equal(state.dataUrl, null);
    assert.equal(state.missing, missing);
  }
  icons.cache.clear();
  assert.equal((await icons.request({ type: 'getSiteIcon', rpId: 'example.com' }, menuSender)).missing, false);
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

test('website icons: only the menu records a missing icon', async () => {
  const icons = background(true);
  await assert.rejects(icons.request({ type: 'markSiteIconMissing', rpId: 'example.com' }, pageSender), { name: 'SecurityError' });
  assert.deepEqual(icons.calls, []);
  assert.equal((await icons.request({ type: 'markSiteIconMissing', rpId: 'example.com' }, menuSender)).saved, true);
  assert.deepEqual(icons.calls, ['enabled', ['missing', 'example.com']]);
});

test('menu icons: a remembered miss never contacts Google', async () => {
  const icons = menuIcons({ missing: true });
  assert.equal(await icons.loadMenuSiteIcon('example.com'), null);
  assert.equal(icons.requests.length, 0);
});

test('menu icons: only a 404 is remembered as a missing icon', async () => {
  const icons = menuIcons({ response: () => new Response(imageBytes, { status: 404, headers: { 'content-type': 'image/png' } }) });
  assert.equal(await icons.loadMenuSiteIcon('example.com'), null);
  assert.deepEqual(icons.missed, ['example.com']);
  assert.equal(await icons.loadMenuSiteIcon('example.com'), null);
  assert.equal(icons.requests.length, 1);

  for (const response of [
    () => new Response('', { status: 500 }),
    () => new Response('', { status: 429 }),
    () => Promise.reject(new TypeError('Failed to fetch')),
  ]) {
    const failing = menuIcons({ response });
    assert.equal(await failing.loadMenuSiteIcon('example.com'), null);
    assert.deepEqual(failing.missed, []);
  }
});

test('menu icons: at most four Google downloads run at once', async () => {
  const downloads = heldDownloads();
  const icons = menuIcons({ response: downloads.response });
  const loads = Array.from({ length: 6 }, (_, index) => icons.loadMenuSiteIcon(`site${index}.example`));
  await until(() => icons.requests.length === 4);
  await ticks();
  assert.equal(icons.requests.length, 4);
  downloads.release();
  await until(() => icons.requests.length === 5);
  while (icons.requests.length < 6 || downloads.held) {
    if (downloads.held) downloads.release();
    await ticks(1);
  }
  assert.deepEqual(await Promise.all(loads), Array(6).fill(ICON));
});

test('menu icons: queued downloads for rows no longer shown are skipped', async () => {
  const downloads = heldDownloads();
  const icons = menuIcons({ response: downloads.response });
  const busy = Array.from({ length: 4 }, (_, index) => icons.loadMenuSiteIcon(`busy${index}.example`));
  await until(() => icons.requests.length === 4);

  const scrolledPast = icons.loadMenuSiteIcon('scrolled-past.example', () => false);
  // One row gone, one shown: download stays
  const shared = icons.loadMenuSiteIcon('shared.example', () => false);
  icons.loadMenuSiteIcon('shared.example', () => true);
  await ticks();

  downloads.release();
  await until(() => icons.requests.length === 5);
  assert.equal(requested(icons, 'scrolled-past.example'), false);
  assert.equal(requested(icons, 'shared.example'), true);
  assert.equal(await scrolledPast, undefined);

  while (downloads.held) {
    downloads.release();
    await ticks(1);
  }
  assert.equal(await shared, ICON);
  assert.deepEqual(await Promise.all(busy), Array(4).fill(ICON));
});

function observedMenuIcons(state) {
  let observer;
  // With new, returns the observer
  function FakeIntersectionObserver(callback) {
    const targets = new Set();
    observer = {
      callback,
      targets,
      observe(target) { targets.add(target); },
      unobserve(target) { targets.delete(target); },
      disconnect() { targets.clear(); },
    };
    return observer;
  }
  const icons = menuIcons(state, { IntersectionObserver: FakeIntersectionObserver });
  return {
    ...icons,
    get observer() { return observer; },
    scroll(target, isIntersecting) { observer.callback([{ target, isIntersecting }]); },
  };
}

test('menu icons: rows ask for icons only while on screen', async () => {
  const icons = observedMenuIcons();
  const shown = [];
  const row = { isConnected: true };
  const offscreen = { isConnected: true };
  icons.watchMenuSiteIcon(row, 'row.example', (dataUrl) => shown.push(['row', dataUrl]));
  icons.watchMenuSiteIcon(offscreen, 'offscreen.example', (dataUrl) => shown.push(['offscreen', dataUrl]));
  await ticks();
  assert.equal(icons.requests.length, 0);

  icons.scroll(row, true);
  await until(() => shown.length === 1);
  assert.deepEqual(shown, [['row', ICON]]);
  assert.equal(icons.requests.length, 1);
  assert.equal(icons.observer.targets.has(row), false);
  assert.equal(icons.observer.targets.has(offscreen), true);
});

test('menu icons: a row hidden before its download starts asks again when shown', async () => {
  const downloads = heldDownloads();
  const icons = observedMenuIcons({ response: downloads.response });
  const busy = Array.from({ length: 4 }, (_, index) => icons.loadMenuSiteIcon(`busy${index}.example`));
  await until(() => icons.requests.length === 4);

  const shown = [];
  const row = { isConnected: true };
  icons.watchMenuSiteIcon(row, 'row.example', (dataUrl) => shown.push(dataUrl));
  icons.scroll(row, true);
  await ticks();
  icons.scroll(row, false);
  downloads.release();
  await ticks();
  assert.equal(requested(icons, 'row.example'), false);

  icons.scroll(row, true);
  await until(() => requested(icons, 'row.example'));
  while (downloads.held) {
    downloads.release();
    await ticks(1);
  }
  await until(() => shown.length === 1);
  assert.deepEqual(shown, [ICON]);
  await Promise.all(busy);
});

test('website icons: the passkey list prunes stale icons without waiting for it', async () => {
  let finish;
  const icons = background(true, { prune: () => new Promise((resolve) => { finish = resolve; }) });
  const prunes = () => icons.calls.filter((call) => call === 'prune').length;
  const state = await Promise.race([
    icons.request({ type: 'getSiteIcon' }, menuSender),
    ticks().then(() => 'waited for pruning'),
  ]);
  assert.equal(state.enabled, true);
  assert.equal(prunes(), 1);

  // A render mid-pass adds one more pass
  await icons.request({ type: 'getSiteIcon' }, menuSender);
  await icons.request({ type: 'getSiteIcon' }, menuSender);
  assert.equal(prunes(), 1);
  finish();
  await until(() => prunes() === 2);
  finish();
  await ticks();
  assert.equal(prunes(), 2);

  const disabled = background(false);
  await disabled.request({ type: 'getSiteIcon' }, menuSender);
  await ticks();
  assert.deepEqual(disabled.calls, ['enabled']);
});
