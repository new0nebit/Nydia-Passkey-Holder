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
// included. local holds the hosts Nydia asked access to. saved is what
// getSettings answers, and saveResult a save's answer, or a function to hold
// it back.
function browserMock({
  grant = true, granted = false, held = [], saved = SAVED, saveResult = { status: 'ok' },
  local = new Map(), scheme = 'chrome-extension',
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
    api, calls, local,
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
    this.attributes = new Map();
    this.classes = new Set();
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
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  get classList() {
    const classes = this.classes;
    return {
      toggle: (name, force = !classes.has(name)) => { if (force) classes.add(name); else classes.delete(name); },
      contains: (name) => classes.has(name),
    };
  }
  get isConnected() { return this.root === true || (this.parent?.isConnected ?? false); }
  replaceChildren() {
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
const fire = (element, type, event = {}) => {
  for (const [name, listener] of element.listeners) if (name === type) listener(event);
};
const inactive = (button) => button.getAttribute('aria-disabled') === 'true';
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The popup's localStorage, shared by the popups a test opens.
function popupStorage() {
  const items = new Map();
  return {
    items,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => { items.set(key, String(value)); },
    removeItem: (key) => { items.delete(key); },
  };
}

function renterd(browser, fetch = async () => { throw new TypeError('offline'); }) {
  return load('renterd', { 'browser-api': browser.api, './logger': logger }, { fetch });
}

// The renterd form as the popup opens it, with the saved settings loaded and
// its private handlers exposed. The calls that opened it are forgotten.
// completed counts exits to Settings or to the list.
async function settingsPage({ browser = browserMock(), fetch = async () => ({ ok: true }), localStorage = popupStorage() } = {}) {
  const requests = [];
  const recordingFetch = (url, options) => {
    requests.push(url);
    return fetch(url, options);
  };
  const access = renterd(browser, recordingFetch);
  const list = Object.assign(new FakeElement('div'), { root: true });
  const doc = {
    activeElement: null,
    listeners: [],
    addEventListener(type, listener) { this.listeners.push([type, listener]); },
    removeEventListener(type, listener) { this.listeners = this.listeners.filter(([, other]) => other !== listener); },
  };
  const popup = { close() { browser.calls.push(['close']); } };
  const iconSettings = async () => new FakeElement('div');
  const settings = load('settings', { 'browser-api': browser.api, './logger': logger, './renterd': access, './siteIcons/settings': { iconSettings } }, {
    fetch: recordingFetch,
    FormData: class {
      constructor(form) { this.form = form; }
      get(name) { return this.form.elements.namedItem(name)?.value ?? null; }
    },
    window: popup,
    localStorage,
    document: Object.assign(doc, {
      getElementById: (id) => (id === 'passkey-list' ? list : null),
      querySelector: () => null,
      createElement: (tagName) => new FakeElement(tagName),
    }),
  }, '\nexports.saveSettingsFromForm = saveSettingsFromForm;\n');
  const notices = [];
  settings.setNotificationDisplayer({ showNotification: (...notice) => notices.push(notice) });
  let toList = 0;
  settings.setOnSettingsComplete(() => { toList += 1; });
  const completed = () => toList + Number(list.byClass('settings-title')?.textContent === 'Settings');

  await settings.showRenterdSettings();
  browser.calls.length = 0;
  const form = list.find((element) => element.tagName === 'form');
  const value = (name) => form.elements.namedItem(name).value;
  const button = form.find((element) => element.className === 'button button-indigo');
  const keydown = (key) => { for (const [, listener] of [...doc.listeners]) listener({ key }); };
  return { settings, browser, requests, notices, form, value, button, completed, document: doc, keydown };
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
  assert.deepEqual(page.browser.types(), ['saveSettings', 'tracked', 'contains']);
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

test('a failed save stays on the form, keeps the input and takes no access away', async () => {
  const browser = browserMock({ held: [...OLD_ORIGINS], local: tracked('192.0.2.20'), saveResult: { error: 'Disk full' } });
  const page = await settingsPage({ browser });
  type(page.form, 'bucketName', 'other');
  await submit(page.form);
  assert.deepEqual(page.notices, [['error', 'Error!', 'Failed to save settings.']]);
  assert.equal(page.completed(), 0);
  assert.equal(page.value('bucketName'), 'other');
  assert.equal(inactive(page.button), true);
  assert.deepEqual(browser.held(), OLD_ORIGINS);
  assert.ok(!browser.types().includes('remove'));
});

test('Back leaves the form and takes no access away', async () => {
  const browser = browserMock({ held: [...OLD_ORIGINS, ...SAVED_ORIGINS], local: tracked('192.0.2.20', '192.0.2.10') });
  const page = await settingsPage({ browser });
  type(page.form, 'serverAddress', 'renterd.example.com');
  page.form.button('Back').onclick();
  await settle();
  assert.equal(page.completed(), 1);
  assert.deepEqual(browser.held(), [...OLD_ORIGINS, ...SAVED_ORIGINS]);
  assert.ok(!browser.types().includes('saveSettings'));
});

test('without a saved server, all the access Nydia asked for goes', async () => {
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

test('Test Connection waits for Save and tests only saved settings', async () => {
  const page = await settingsPage({ browser: browserMock({ granted: true }) });
  assert.equal(page.button.textContent, 'Test Connection');
  assert.equal(inactive(page.button), false);

  type(page.form, 'serverAddress', 'renterd.example.com');
  assert.equal(page.button.textContent, 'Test Connection');
  assert.equal(inactive(page.button), true);
  await page.button.onclick();
  assert.equal(page.requests.length, 0);
  // The same as saved once in canonical form
  type(page.form, 'serverAddress', ' 192.0.2.10 ');
  assert.equal(inactive(page.button), false);

  type(page.form, 'serverAddress', 'Renterd.Example.com');
  await submit(page.form);
  assert.equal(page.value('serverAddress'), 'renterd.example.com');
  assert.equal(inactive(page.button), false);
  await page.button.onclick();
  assert.equal(page.requests.at(-1), 'https://renterd.example.com:9980/api/worker/state');

  // Nothing saved yet: the hint asks for a first save, not about changes
  const empty = await settingsPage({ browser: browserMock({ saved: null }) });
  const hint = empty.form.byClass('save-hint');
  assert.equal(inactive(empty.button), true);
  assert.equal(hint.textContent, 'Save your settings to test.');
  for (const [name, value] of Object.entries({ ...SAVED, serverPort: '9980' })) type(empty.form, name, value);
  assert.equal(hint.textContent, 'Save your settings to test.');
  await submit(empty.form);
  assert.equal(inactive(empty.button), false);
  type(empty.form, 'bucketName', 'other');
  assert.equal(hint.textContent, 'Unsaved changes. Save to test.');
});

test('an unsaved form explains Test Connection on hover, focus or click, until Esc', async () => {
  const page = await settingsPage();
  const group = page.form.byClass('test-connection');
  const hint = page.form.byClass('save-hint');
  const buttons = page.form.byClass('button-container');
  const open = () => group.classList.contains('hint-open');

  // Saved: nothing to explain, and the hint is not attached
  fire(group, 'pointerenter');
  await wait(250);
  assert.equal(open(), false);
  assert.equal(page.button.getAttribute('aria-describedby'), null);
  fire(group, 'pointerleave');

  type(page.form, 'bucketName', 'other');
  assert.equal(hint.textContent, 'Unsaved changes. Save to test.');
  assert.equal(page.button.getAttribute('aria-describedby'), hint.id);

  // A short delay on hover; Save is ringed while the hint shows
  fire(group, 'pointerenter');
  await wait(100);
  assert.equal(open(), false);
  await wait(150);
  assert.equal(open(), true);
  assert.equal(buttons.classList.contains('hint-open'), true);
  page.keydown('Escape');
  assert.equal(open(), false);
  assert.equal(buttons.classList.contains('hint-open'), false);
  fire(group, 'pointerleave');

  // A click shows it at once and tests nothing
  await page.button.onclick();
  assert.equal(open(), true);
  assert.equal(page.requests.length, 0);
  fire(group, 'pointerleave');
  assert.equal(open(), false);

  // Keyboard focus shows it, Esc hides it, and focus again shows it
  page.document.activeElement = page.button;
  fire(page.button, 'focus');
  assert.equal(open(), true);
  page.keydown('Escape');
  assert.equal(open(), false);
  fire(page.button, 'focus');
  assert.equal(open(), true);

  // Saving ends it and detaches it
  await submit(page.form);
  assert.equal(open(), false);
  assert.equal(page.button.getAttribute('aria-describedby'), null);

  // Leaving the form drops its Esc listener at the next key
  page.form.button('Back').onclick();
  page.keydown('Escape');
  assert.equal(page.document.listeners.length, 0);
});

test('a late access check cannot offer access after an edit, Save or Back', async () => {
  for (const action of ['edit', 'save', 'back']) {
    const browser = browserMock();
    let answer;
    let checks = 0;
    browser.api.permissions.contains = () => ++checks === 1
      ? new Promise((resolve) => { answer = resolve; })
      : Promise.resolve(true);
    const page = await settingsPage({ browser });
    const testing = page.button.onclick();
    if (action === 'back') page.form.button('Back').onclick();
    else {
      type(page.form, 'serverAddress', '192.0.2.20');
      if (action === 'save') await submit(page.form);
    }
    answer(false);
    await testing;
    assert.equal(page.form.byClass('access-request'), null, action);
    assert.equal(page.requests.length, 0, action);
    assert.deepEqual(page.notices, action === 'save'
      ? [['success', 'Success!', 'Settings saved successfully.']]
      : [], action);
  }
});

test('a late connection result cannot notify or unlock a newer test', async () => {
  for (const oldResponse of [{ ok: true }, { ok: false, status: 401 }]) {
    const answers = [];
    const page = await settingsPage({
      browser: browserMock({ granted: true }),
      fetch: () => new Promise((resolve) => answers.push(resolve)),
    });
    const first = page.button.onclick();
    await settle();
    type(page.form, 'serverAddress', '192.0.2.20');
    await submit(page.form);
    page.notices.length = 0;
    const second = page.button.onclick();
    await settle();
    assert.equal(answers.length, 2);
    answers[0](oldResponse);
    await first;
    assert.deepEqual(page.notices, []);
    assert.equal(page.button.textContent, 'Testing...');
    assert.equal(inactive(page.button), true);
    answers[1]({ ok: true });
    await second;
    assert.deepEqual(page.notices, [['success', 'Success!', 'Connection successful.']]);
    assert.equal(inactive(page.button), false);
  }
});

test('leaving the form ignores a late connection result', async () => {
  let answer;
  const page = await settingsPage({
    browser: browserMock({ granted: true }),
    fetch: () => new Promise((resolve) => { answer = resolve; }),
  });
  const testing = page.button.onclick();
  await settle();
  page.form.button('Back').onclick();
  answer({ ok: true });
  await testing;
  assert.equal(page.completed(), 1);
  assert.deepEqual(page.notices, []);
});

test('Allow access in the form brings the next popup back to it, unless the popup stays open', async () => {
  const localStorage = popupStorage();
  // The prompt never answers: it has closed the popup.
  const closed = await settingsPage({ browser: browserMock({ grant: () => new Promise(() => {}) }), localStorage });
  await closed.button.onclick();
  void closed.form.button('Allow access').onclick();
  assert.equal(closed.settings.takeRenterdReopen(), true);
  assert.equal(closed.settings.takeRenterdReopen(), false);

  const open = await settingsPage({ browser: browserMock({ grant: false }), localStorage });
  await open.button.onclick();
  await open.form.button('Allow access').onclick();
  assert.equal(localStorage.items.size, 0);

  // Sync and Backup ask from the passkey list, which the popup opens anyway.
  const list = await settingsPage({ browser: browserMock({ grant: () => new Promise(() => {}) }), localStorage });
  void list.settings.accessRequestView('192.0.2.10', () => {}).find((element) => element.tagName === 'button').onclick();
  assert.equal(localStorage.items.size, 0);
});

test('Test Connection never prompts: without access it offers Allow access, and tests once allowed', async () => {
  const page = await settingsPage();
  await page.button.onclick();
  assert.deepEqual(page.browser.types(), ['contains']);
  assert.equal(page.requests.length, 0);
  assert.deepEqual(page.notices, []);
  assert.equal(page.form.byClass('access-request').children[0].textContent, 'Nydia needs your permission to reach 192.0.2.10.');
  assert.equal(inactive(page.button), false);

  const allowed = page.form.button('Allow access').onclick();
  assert.deepEqual(page.browser.calls.slice(-2), [['access', ...SAVED_ORIGINS], ['track', 'renterdAccess:192.0.2.10']]);
  await allowed;
  assert.equal(page.requests.length, 1);
  assert.deepEqual(page.notices, [['success', 'Success!', 'Connection successful.']]);
  assert.equal(page.form.byClass('access-request'), null);
  // Testing saves nothing and stays on the form.
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
