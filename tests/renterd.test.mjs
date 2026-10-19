import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

import { createIndexedDB } from './helpers/indexedDB.mjs';

const require = createRequire(import.meta.url);
const base64url = require('../.test-build/utils/base64url.js');
const logger = { logDebug() {}, logInfo() {}, logWarn() {}, logError() {} };
const SAVED = { serverAddress: '192.0.2.10', serverPort: 9980, password: 'secret', bucketName: 'passkeys' };
const SAVED_ORIGINS = ['http://192.0.2.10/*', 'https://192.0.2.10/*'];
const OLD_ORIGINS = ['http://192.0.2.20/*', 'https://192.0.2.20/*'];
const MANIFEST_ORIGINS = ['https://*/*', 'http://localhost/*'];

// The hosts Nydia recorded as asked for, as local storage keeps them.
const tracked = (...hosts) => new Map(hosts.map((host) => [`renterdAccess:${host}`, true]));
const settle = () => new Promise((resolve) => setTimeout(resolve));

function load(file, imports, globals = {}, extra = '') {
  const context = {
    exports: {}, Error, DOMException, AbortController, setTimeout, clearTimeout, btoa, atob, JSON,
    Uint8Array, ArrayBuffer, TextEncoder, TextDecoder,
    require(name) {
      assert.ok(name in imports, `Unexpected import: ${name}`);
      return imports[name];
    },
    ...globals,
  };
  runInNewContext(readFileSync(new URL(`../.test-build/${file}.js`, import.meta.url), 'utf8') + extra, context);
  return context.exports;
}

// Records browser calls in order. grant answers the access prompt; a function
// lets a test hold the answer back, as when the prompt closes the popup.
// granted is what the browser allows, and an allowed prompt adds to it.
// held lists the origins the browser reports as granted, manifest ones
// included. session is session storage, which outlives the popup; local holds
// the hosts Nydia asked access to. saved is what getSettings answers, and
// saveResult a save's answer, or a function to hold it back.
function browserMock({
  grant = true, granted = false, held = [], saved = SAVED, saveResult = { status: 'ok' },
  session = new Map(), local = new Map(), scheme = 'chrome-extension',
} = {}) {
  const calls = [];
  const api = {
    permissions: {
      request(options) {
        calls.push(['access', ...options.origins]);
        return (typeof grant === 'function' ? grant() : Promise.resolve(grant)).then((answer) => {
          if (answer) granted = true;
          return answer;
        });
      },
      contains(options) {
        calls.push(['contains', ...options.origins]);
        return Promise.resolve(granted);
      },
      getAll() {
        calls.push(['getAll']);
        return Promise.resolve({ origins: [...held] });
      },
      remove(options) {
        calls.push(['remove', ...options.origins]);
        held = held.filter((origin) => !options.origins.includes(origin));
        return Promise.resolve(true);
      },
    },
    runtime: {
      sendMessage(message) {
        calls.push([message.type, message.settings]);
        if (message.type === 'getSettings') return Promise.resolve(saved);
        return typeof saveResult === 'function' ? saveResult() : Promise.resolve(saveResult);
      },
      getManifest() {
        return { content_scripts: [{ matches: MANIFEST_ORIGINS }] };
      },
      getURL(path) {
        return `${scheme}://nydia/${path}`;
      },
    },
    storage: {
      session: {
        get(key) {
          calls.push(['draft:get']);
          return Promise.resolve(session.has(key) ? { [key]: structuredClone(session.get(key)) } : {});
        },
        set(items) {
          calls.push(['draft:set']);
          for (const [key, value] of Object.entries(items)) session.set(key, structuredClone(value));
          return Promise.resolve();
        },
        remove(key) {
          calls.push(['draft:remove']);
          session.delete(key);
          return Promise.resolve();
        },
      },
      local: {
        get(keys) {
          assert.equal(keys, null);
          calls.push(['tracked']);
          return Promise.resolve(Object.fromEntries(local));
        },
        set(items) {
          calls.push(['track', ...Object.keys(items)]);
          for (const [key, value] of Object.entries(items)) local.set(key, value);
          return Promise.resolve();
        },
        remove(keys) {
          calls.push(['untrack', ...[keys].flat()]);
          for (const key of [keys].flat()) local.delete(key);
          return Promise.resolve();
        },
      },
    },
  };
  return {
    api, calls, session, local,
    held: () => held,
    setSaved: (settings) => { saved = settings; },
    types: () => calls.map(([type]) => type),
  };
}

// Just enough DOM for the settings form to render and take clicks.
class FakeElement {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.parent = null;
    this.listeners = [];
    this.value = '';
    this.disabled = false;
    this.readOnly = false;
  }
  querySelectorAll(tagName) {
    const found = [];
    const visit = (element) => {
      for (const child of element.children) {
        if (child.tagName === tagName) found.push(child);
        visit(child);
      }
    };
    visit(this);
    return found;
  }
  appendChild(child) { return this.insertBefore(child, null); }
  prepend(child) { return this.insertBefore(child, this.children[0] ?? null); }
  append(...children) {
    for (const child of children) {
      this.appendChild(typeof child === 'string' ? Object.assign(new FakeElement('#text'), { textContent: child }) : child);
    }
  }
  get text() { return this.children.length ? this.children.map((child) => child.text).join('') : this.textContent ?? ''; }
  insertBefore(child, before) {
    child.remove();
    child.parent = this;
    const index = before ? this.children.indexOf(before) : this.children.length;
    this.children.splice(index, 0, child);
    return child;
  }
  remove() {
    this.parent?.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }
  addEventListener(type, listener) { this.listeners.push([type, listener]); }
  set innerHTML(html) {
    assert.equal(html, '');
    for (const child of [...this.children]) child.remove();
  }
  get elements() { return { namedItem: (name) => this.find((element) => element.name === name) }; }
  find(match) {
    for (const child of this.children) {
      const found = match(child) ? child : child.find(match);
      if (found) return found;
    }
    return null;
  }
  button(label) { return this.find((element) => element.tagName === 'button' && element.textContent === label); }
  byClass(className) { return this.find((element) => element.className === className); }
}

// Types into a field as the user does: the field and then the form hear it.
function type(form, name, value) {
  const input = form.elements.namedItem(name);
  input.value = value;
  for (const element of [input, form]) {
    for (const [event, listener] of element.listeners) if (event === 'input') listener({ target: input });
  }
}

const submit = (form) => form.onsubmit({ preventDefault() {} });

function renterd(browser, fetch = async () => { throw new TypeError('offline'); }) {
  return load('renterd', { 'browser-api': browser.api, './logger': logger }, { fetch });
}

// The settings form as the popup opens it, with the saved settings loaded and
// its private handlers exposed. The calls that opened it are forgotten.
async function settingsPage({ browser = browserMock(), fetch = async () => ({ ok: true }) } = {}) {
  const requests = [];
  const recordingFetch = (url, options) => {
    requests.push(url);
    return fetch(url, options);
  };
  const access = renterd(browser, recordingFetch);
  const list = new FakeElement('div');
  const popup = { close() { browser.calls.push(['close']); } };
  const settings = load('settings', { 'browser-api': browser.api, './logger': logger, './renterd': access }, {
    fetch: recordingFetch,
    FormData: class {
      constructor(form) { this.form = form; }
      get(name) { return this.form.elements.namedItem(name)?.value ?? null; }
    },
    window: popup,
    document: {
      getElementById: (id) => (id === 'passkey-list' ? list : null),
      querySelector: () => null,
      createElement: (tagName) => new FakeElement(tagName),
    },
  }, '\nexports.saveSettingsFromForm = saveSettingsFromForm;\n');
  const notices = [];
  settings.setNotificationDisplayer({ showNotification: (...notice) => notices.push(notice) });
  let completed = 0;
  settings.setOnSettingsComplete(() => { completed += 1; });

  await settings.showSettingsForm();
  browser.calls.length = 0;
  const form = list.find((element) => element.tagName === 'form');
  const value = (name) => form.elements.namedItem(name).value;
  return { settings, browser, requests, notices, form, value, button: form.button('Test Connection'), completed: () => completed };
}

// The real store on an in-memory NydiaDB holding the given renterd settings.
function vault(stored) {
  const indexedDB = createIndexedDB();
  const settings = new Map(stored ? [['renterdSettings', { ...stored, id: 'renterdSettings' }]] : []);
  indexedDB.databases.set('NydiaDB', {
    version: 4,
    stores: new Map([
      ['passkeys', { keyPath: 'uniqueId', data: new Map() }],
      ['settings', { keyPath: 'id', data: settings }],
    ]),
  });
  const store = load('store', { './logger': logger, './utils/base64url': base64url }, { indexedDB, crypto });
  return { store, database: indexedDB.databases.get('NydiaDB'), saved: () => settings.get('renterdSettings') };
}

test('renterd access: only the configured host is requested, over both schemes', async () => {
  const access = renterd(browserMock());
  assert.deepEqual([...access.renterdOrigins('192.0.2.10')], ['http://192.0.2.10/*', 'https://192.0.2.10/*']);
  // Settings saved before addresses were kept in lower case still match.
  assert.deepEqual([...access.renterdOrigins('Renterd.EXAMPLE')], ['http://renterd.example/*', 'https://renterd.example/*']);
  for (const address of ['*', '*.example.com', 'https://example.com', 'example.com/path', 'host:9980', 'user@host', '']) {
    assert.throws(() => access.renterdOrigins(address));
  }

  // A refused or failed prompt means no access.
  assert.equal(await renterd(browserMock({ grant: false })).requestRenterdAccess('localhost'), false);
  const failing = renterd(browserMock({ grant: () => Promise.reject(new Error('Not a user gesture')) }));
  assert.equal(await failing.requestRenterdAccess('localhost'), false);
});

test('renterd protocol: HTTPS is tried first, then HTTP', async () => {
  const urls = [];
  const access = renterd(browserMock(), async (url) => {
    urls.push(url);
    if (url.startsWith('https:')) throw new TypeError('TLS error');
    return { ok: true };
  });
  assert.equal(await access.detectProtocol(SAVED), 'http');
  assert.deepEqual(urls, ['https://192.0.2.10:9980/api/worker/state', 'http://192.0.2.10:9980/api/worker/state']);
  await assert.rejects(renterd(browserMock()).detectProtocol(SAVED), /Failed to connect to renterd server/);
});

test('Save never prompts and stays on the form, offering Allow access only without access', async () => {
  // No access, and the prompt never answers, as when it has closed the popup.
  const page = await settingsPage({ browser: browserMock({ grant: () => new Promise(() => {}) }) });
  await submit(page.form);
  assert.deepEqual(page.browser.types(), ['saveSettings', 'draft:remove', 'tracked', 'contains']);
  assert.deepEqual(page.notices, [['success', 'Success!', 'Settings saved successfully.']]);
  assert.equal(page.completed(), 0);

  const request = page.form.byClass('access-request');
  assert.equal(request.children[0].textContent, 'Nydia needs your permission to reach 192.0.2.10.');
  assert.equal(page.form.children.indexOf(request) + 1, page.form.children.indexOf(page.form.byClass('button-container')));

  void page.form.button('Allow access').onclick();
  // Recording the host starts in the same click, before the prompt can close the popup.
  assert.deepEqual(page.browser.calls.slice(-2), [['access', ...SAVED_ORIGINS], ['track', 'renterdAccess:192.0.2.10']]);

  // The request was for the saved address, so editing takes it away.
  type(page.form, 'serverAddress', 'renterd.example.com');
  assert.equal(page.form.byClass('access-request'), null);

  // With access, Save offers nothing, and takes away what Test Connection offered.
  const browser = browserMock();
  const allowed = await settingsPage({ browser });
  await allowed.button.onclick();
  assert.notEqual(allowed.form.byClass('access-request'), null);
  browser.api.permissions.contains = () => Promise.resolve(true);
  await submit(allowed.form);
  assert.deepEqual(allowed.notices, [['success', 'Success!', 'Settings saved successfully.']]);
  assert.equal(allowed.completed(), 0);
  assert.equal(allowed.form.byClass('access-request'), null);
  assert.ok(!browser.types().includes('access'));
});

test('Allow access after Save stays on the form, allowed or refused', async () => {
  for (const grant of [true, false]) {
    const page = await settingsPage({ browser: browserMock({ grant }) });
    await submit(page.form);
    const allow = page.form.button('Allow access');
    await allow.onclick();
    assert.equal(page.completed(), 0);
    assert.deepEqual(page.notices.at(-1), grant
      ? ['success', 'Success!', 'Access to 192.0.2.10 allowed.']
      : ['error', 'Error!', 'Nydia needs access to 192.0.2.10 to reach renterd.']);
    assert.equal(page.form.byClass('access-request') === null, grant);
    if (!grant) assert.equal(allow.disabled, false);
  }
});

test('Save takes back only the access Nydia asked for other servers, never other access', async () => {
  const tested = ['http://typo.example/*', 'https://typo.example/*'];
  // A site the user allowed for passkeys, and the manifest's own patterns.
  const other = ['https://example.com/*', ...MANIFEST_ORIGINS];
  const browser = browserMock({
    granted: true,
    held: [...OLD_ORIGINS, ...tested, ...SAVED_ORIGINS, ...other, 'https://localhost/*'],
    local: tracked('192.0.2.20', 'typo.example', 'localhost', '192.0.2.10'),
  });
  const page = await settingsPage({ browser });
  await submit(page.form);
  assert.deepEqual(browser.held(), [...SAVED_ORIGINS, ...other]);
  assert.deepEqual([...browser.local.keys()], ['renterdAccess:192.0.2.10']);
});

test('a failed save stays on the form, keeps the draft and takes no access away', async () => {
  const browser = browserMock({ held: [...OLD_ORIGINS], local: tracked('192.0.2.20'), saveResult: { error: 'Disk full' } });
  const page = await settingsPage({ browser });
  type(page.form, 'bucketName', 'other');
  await submit(page.form);
  assert.deepEqual(page.notices, [['error', 'Error!', 'Failed to save settings.']]);
  assert.equal(page.completed(), 0);
  assert.equal(browser.session.size, 1);
  assert.deepEqual(browser.held(), OLD_ORIGINS);
  assert.ok(!browser.types().includes('remove'));
});

test('Back keeps the saved server, read afresh, and takes nothing when it cannot be read', async () => {
  const browser = browserMock({ held: [...OLD_ORIGINS, ...SAVED_ORIGINS], local: tracked('192.0.2.20', '192.0.2.10') });
  const page = await settingsPage({ browser });
  page.form.button('Back').onclick();
  await settle();
  assert.deepEqual(browser.held(), SAVED_ORIGINS);

  const unreadable = browserMock({ held: [...SAVED_ORIGINS], local: tracked('192.0.2.10') });
  const failing = await settingsPage({ browser: unreadable });
  unreadable.setSaved({ error: 'Could not establish connection.' });
  failing.form.button('Back').onclick();
  await settle();
  assert.deepEqual(unreadable.held(), SAVED_ORIGINS);

  const none = browserMock({ held: [...SAVED_ORIGINS, ...MANIFEST_ORIGINS], local: tracked('192.0.2.10', 'localhost') });
  await renterd(none).keepRenterdAccessOnly(null);
  assert.deepEqual(none.held(), MANIFEST_ORIGINS);
  assert.equal(none.local.size, 0);
});

test('an origin the browser refuses to remove does not keep the rest, and is only logged', async () => {
  const browser = browserMock({ held: [...OLD_ORIGINS], local: tracked('192.0.2.20') });
  const remove = browser.api.permissions.remove;
  browser.api.permissions.remove = (options) => options.origins[0].startsWith('http:')
    ? Promise.reject(new Error('You cannot remove required permissions.'))
    : remove(options);
  await renterd(browser).keepRenterdAccessOnly('192.0.2.10');
  assert.deepEqual(browser.held(), ['http://192.0.2.20/*']);
  assert.equal(browser.local.size, 0);

  const clean = browserMock({ held: [...SAVED_ORIGINS], local: tracked('192.0.2.10') });
  await renterd(clean).keepRenterdAccessOnly('192.0.2.10');
  assert.ok(!clean.types().includes('getAll'));
});

test('the address takes one form, in lower case, wherever it is saved, asked for or kept', async () => {
  const origins = ['http://renterd.example/*', 'https://renterd.example/*'];
  const browser = browserMock({ held: [...origins], local: tracked('renterd.example') });
  const page = await settingsPage({ browser });
  type(page.form, 'serverAddress', ' RENTERD.Example ');
  await submit(page.form);
  assert.equal(browser.calls.find(([type]) => type === 'saveSettings')[1].serverAddress, 'renterd.example');
  // The browser reports the host in lower case: the saved server keeps its access.
  assert.deepEqual(browser.held(), origins);

  await page.form.button('Allow access').onclick();
  assert.deepEqual(browser.calls.find(([type]) => type === 'access'), ['access', ...origins]);
  assert.ok(browser.local.has('renterdAccess:renterd.example'));
});

test('the form is locked while it is saved', async () => {
  let finish;
  const browser = browserMock({ saveResult: () => new Promise((resolve) => { finish = resolve; }) });
  const page = await settingsPage({ browser });
  const saving = submit(page.form);
  const inputs = page.form.querySelectorAll('input');
  assert.ok(inputs.every((input) => input.readOnly));
  assert.ok(page.form.querySelectorAll('button').every((button) => button.disabled));

  finish({ status: 'ok' });
  await saving;
  assert.ok(inputs.every((input) => !input.readOnly));
  assert.ok(page.form.querySelectorAll('button').every((button) => !button.disabled));
});

test('Allow access closes the popup in Firefox, where the prompt opens under it, and only there', async () => {
  for (const [scheme, closes] of [['moz-extension', true], ['chrome-extension', false]]) {
    // The prompt never answers: the user has not got to it yet.
    const browser = browserMock({ scheme, grant: () => new Promise(() => {}) });
    const page = await settingsPage({ browser });
    await submit(page.form);
    void page.form.button('Allow access').onclick();
    // The request goes out, and recording its host starts, before the popup closes.
    assert.deepEqual(browser.types().slice(-3), closes ? ['access', 'track', 'close'] : ['contains', 'access', 'track']);
  }
});

test('Save keeps the protocol for the same server and clears it for a new address or port', async () => {
  const existing = { ...SAVED, serverProtocol: 'https' };
  for (const [change, protocol] of [[{}, 'https'], [{ serverAddress: 'renterd.example.com' }, undefined], [{ serverPort: '443' }, undefined]]) {
    const page = await settingsPage();
    for (const [name, value] of Object.entries(change)) type(page.form, name, value);
    assert.ok(await page.settings.saveSettingsFromForm(page.form, existing));
    assert.equal(page.browser.calls.find(([type]) => type === 'saveSettings')[1].serverProtocol, protocol);
  }
});

test('input that is not saved outlives the popup until Save or Back', async () => {
  const session = new Map();
  const page = await settingsPage({ browser: browserMock({ session }) });
  assert.equal(page.form.byClass('unsaved-changes'), null);
  type(page.form, 'serverAddress', 'renterd.example.com');
  assert.deepEqual(page.browser.types(), ['draft:set']);
  assert.deepEqual({ ...await page.settings.getDraft() }, { ...SAVED, serverPort: '9980', serverAddress: 'renterd.example.com' });

  // As if the access prompt closed the popup: it opens again on the draft.
  const reopened = await settingsPage({ browser: browserMock({ session }) });
  assert.equal(reopened.value('serverAddress'), 'renterd.example.com');
  assert.equal(reopened.value('password'), 'secret');
  const notice = reopened.form.byClass('unsaved-changes');
  assert.equal(notice.text, 'Unsaved changes. Press Save to keep them.');
  assert.equal(reopened.form.children.indexOf(notice) + 1, reopened.form.children.indexOf(reopened.form.byClass('button-container')));

  // Allow access goes above it, and the notice stays next to the buttons.
  await reopened.button.onclick();
  assert.equal(reopened.form.children.indexOf(reopened.form.byClass('access-request')) + 1, reopened.form.children.indexOf(notice));
  reopened.form.button('Back').onclick();
  assert.equal(session.size, 0);
  assert.equal(reopened.completed(), 1);
  assert.equal((await settingsPage({ browser: browserMock({ session }) })).value('serverAddress'), '192.0.2.10');

  type(page.form, 'bucketName', 'other');
  const again = await settingsPage({ browser: browserMock({ session }) });
  assert.notEqual(again.form.byClass('unsaved-changes'), null);
  await submit(again.form);
  assert.equal(session.size, 0);
  assert.equal(again.form.byClass('unsaved-changes'), null);
});

test('Test Connection never prompts: without access it offers Allow access, and tests once allowed', async () => {
  const page = await settingsPage();
  await page.button.onclick();
  assert.deepEqual(page.browser.types(), ['contains']);
  assert.equal(page.requests.length, 0);
  assert.deepEqual(page.notices, []);
  assert.equal(page.form.byClass('access-request').children[0].textContent, 'Nydia needs your permission to reach 192.0.2.10.');
  assert.equal(page.button.disabled, false);

  const allowed = page.form.button('Allow access').onclick();
  assert.deepEqual(page.browser.calls.slice(-2), [['access', ...SAVED_ORIGINS], ['track', 'renterdAccess:192.0.2.10']]);
  await allowed;
  assert.equal(page.requests.length, 1);
  assert.deepEqual(page.notices, [['success', 'Success!', 'Connection successful.']]);
  assert.equal(page.form.byClass('access-request'), null);
  // The settings are not saved, so the form stays.
  assert.equal(page.completed(), 0);
  assert.ok(!page.browser.types().includes('saveSettings'));
});

test('Test Connection with access tests at once, and a refused prompt keeps Allow access', async () => {
  const page = await settingsPage({ browser: browserMock({ granted: true }) });
  await page.button.onclick();
  assert.deepEqual(page.browser.types(), ['contains']);
  assert.equal(page.requests.length, 1);
  assert.equal(page.form.byClass('access-request'), null);

  const refused = await settingsPage({ browser: browserMock({ grant: false }) });
  await refused.button.onclick();
  const allow = refused.form.button('Allow access');
  await allow.onclick();
  assert.equal(refused.requests.length, 0);
  assert.deepEqual(refused.notices, [['error', 'Error!', 'Nydia needs access to 192.0.2.10 to reach renterd.']]);
  assert.equal(allow.disabled, false);
  assert.notEqual(refused.form.byClass('access-request'), null);
});

test('background reports settings saved only once committed, and a failed write as an error', async () => {
  const { store, database, saved } = vault();
  assert.equal((await store.handleMessageInBackground({ type: 'saveSettings', settings: SAVED })).status, 'ok');
  assert.equal(saved().serverAddress, '192.0.2.10');

  database.failWrites = true;
  const result = await store.handleMessageInBackground({ type: 'saveSettings', settings: { ...SAVED, serverAddress: 'other.example' } });
  assert.match(result.error, /Disk full/);
  assert.equal(saved().serverAddress, '192.0.2.10');

  // The write itself succeeds and the commit fails: the save did not happen.
  database.failWrites = false;
  database.failCommit = true;
  const aborted = await store.handleMessageInBackground({ type: 'saveSettings', settings: { ...SAVED, serverAddress: 'other.example' } });
  assert.match(aborted.error, /Commit failed/);
  assert.equal(saved().serverAddress, '192.0.2.10');
});

test('a corrected password does not wait for the check of the old one', async () => {
  const { store } = vault(SAVED);
  const sent = [];
  const answers = [];
  const fetch = (url, options) => {
    sent.push(atob(options.headers.Authorization.slice('Basic '.length)));
    return new Promise((resolve) => answers.push(resolve));
  };
  const sia = load('sia', { './logger': logger, './renterd': renterd(browserMock(), fetch), './store': store }, { fetch });
  const first = sia.getRenterdSettings();
  await settle();
  await store.handleMessageInBackground({ type: 'saveSettings', settings: { ...SAVED, password: 'corrected' } });
  const second = sia.getRenterdSettings();
  await settle();
  assert.deepEqual(sent, ['username:secret', 'username:corrected']);

  for (const answer of answers) answer({ ok: true });
  await Promise.all([first, second]);
});

test('background detects a new server protocol once, saves it and shares it', async () => {
  const { store, saved } = vault(SAVED);
  const urls = [];
  const fetch = async (url) => {
    urls.push(url);
    if (url.startsWith('https:')) throw new TypeError('TLS error');
    return { ok: true };
  };
  const sia = load('sia', { './logger': logger, './renterd': renterd(browserMock(), fetch), './store': store }, { fetch });

  const results = await Promise.all([sia.getRenterdSettings(), sia.getRenterdSettings()]);
  assert.deepEqual(results.map(({ serverProtocol }) => serverProtocol), ['http', 'http']);
  assert.equal(urls.length, 2);
  assert.equal(saved().serverProtocol, 'http');
  assert.equal((await sia.getRenterdSettings()).serverProtocol, 'http');
  assert.equal(urls.length, 2);
});

test('background retries a failed detection and never writes it over newer settings', async () => {
  const { store } = vault(SAVED);
  let online = false;
  const fetch = async () => {
    if (!online) throw new TypeError('offline');
    return { ok: true };
  };
  const sia = load('sia', { './logger': logger, './renterd': renterd(browserMock(), fetch), './store': store }, { fetch });
  await assert.rejects(sia.getRenterdSettings(), /Failed to connect/);
  online = true;
  assert.equal((await sia.getRenterdSettings()).serverProtocol, 'https');

  const moved = vault({ ...SAVED, serverAddress: 'renterd.example.com' });
  await moved.store.saveServerProtocol(SAVED, 'https');
  assert.equal(moved.saved().serverProtocol, undefined);
  assert.equal(moved.saved().serverAddress, 'renterd.example.com');
});

test('a rejected password is reported as such, not as an unreachable server', async () => {
  for (const [rejecting, requests] of [['https:', 1], ['http:', 2]]) {
    const urls = [];
    const access = renterd(browserMock(), async (url) => {
      urls.push(url);
      if (url.startsWith(rejecting)) return { ok: false, status: 401 };
      throw new TypeError('TLS error');
    });
    await assert.rejects(access.detectProtocol(SAVED), { message: access.WRONG_PASSWORD });
    assert.equal(urls.length, requests);
  }

  const page = await settingsPage({ browser: browserMock({ granted: true }), fetch: async () => ({ ok: false, status: 401 }) });
  await page.button.onclick();
  assert.deepEqual(page.notices, [['error', 'Error!', 'renterd rejected the password.']]);

  // Background says so too, when detecting and when uploading.
  const rejecting = async () => ({ ok: false, status: 401, statusText: 'Unauthorized' });
  const { store, saved } = vault(SAVED);
  const sia = load('sia', { './logger': logger, './renterd': renterd(browserMock(), rejecting), './store': store }, { fetch: rejecting, Blob });
  await assert.rejects(sia.getRenterdSettings(), /renterd rejected the password/);
  assert.equal(saved().serverProtocol, undefined);

  const known = vault({ ...SAVED, serverProtocol: 'http' });
  const upload = load('sia', { './logger': logger, './renterd': renterd(browserMock(), rejecting), './store': known.store }, { fetch: rejecting, Blob });
  const result = await upload.uploadPasskeyDirect({ uniqueId: 'passkey', metadata: {}, secret: {}, isSynced: false });
  assert.equal(result.error, 'Failed to backup passkey: renterd rejected the password.');
});
