// Build first: npm test && npm run build:chrome. All mutations use a fresh
// temporary profile and a copy of the extension, never an installed profile.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const repo = fileURLToPath(new URL('../..', import.meta.url));
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'nydia-storage-test-'));
const extension = path.join(temporary, 'extension');
fs.cpSync(path.join(repo, 'build/chrome'), extension, { recursive: true });
// Host permission is only for the local renterd fixture in this disposable copy.
const manifest = JSON.parse(fs.readFileSync(path.join(extension, 'manifest.json')));
manifest.host_permissions = ['http://localhost/*', 'https://localhost/*'];
fs.writeFileSync(path.join(extension, 'manifest.json'), JSON.stringify(manifest));
fs.writeFileSync(path.join(extension, 'storage-test.html'), '<!doctype html><script src="storage-test.js"></script>');
fs.writeFileSync(path.join(extension, 'storage-test.js'), `
const base64 = (() => { const exports = {}; ${fs.readFileSync(path.join(repo, '.test-build/utils/base64url.js'), 'utf8')}; return exports; })();
globalThis.testStore = (() => { const exports = {}; const require = name => name === './utils/base64url' ? base64 : { logDebug() {}, logError() {} };
${fs.readFileSync(path.join(repo, '.test-build/store.js'), 'utf8')}; return exports; })();
`);

let context, fixture, menu, id, settings, origin;
let checks = 0;
const objects = new Map();
const expectedPassword = 'browser-test-password';
const server = http.createServer(async (req, res) => {
  if (req.url === '/') {
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><title>Nydia local RP</title><p>Local WebAuthn test</p>');
    return;
  }
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  if (req.method === 'OPTIONS') { res.end(); return; }
  if (req.headers.authorization !== `Basic ${Buffer.from(`username:${expectedPassword}`).toString('base64')}`) {
    res.statusCode = 401; res.end(); return;
  }
  const url = new URL(req.url, origin);
  res.setHeader('Content-Type', 'application/json');
  if (url.pathname.startsWith('/api/worker/object/')) {
    const name = decodeURIComponent(url.pathname.slice('/api/worker/object/'.length));
    if (req.method === 'PUT') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      objects.set(name, JSON.parse(Buffer.concat(chunks).toString()));
      res.end('{}');
    } else res.end(JSON.stringify(objects.get(name)));
  } else if (url.pathname.startsWith('/api/bus/objects')) {
    res.end(JSON.stringify({ objects: [...objects.keys()].map(key => ({ key })) }));
  } else res.end('{}');
});

const passed = name => { checks++; console.log(`PASS ${name}`); };
const message = value => fixture.evaluate(value => chrome.runtime.sendMessage(value), value);
const row = () => fixture.evaluate(() => globalThis.dbAccess('readonly', 'settings', s => s.get('renterdSettings')));
const putRow = value => fixture.evaluate(value => globalThis.dbAccess('readwrite', 'settings', s => s.put(value)), value);
const records = () => fixture.evaluate(() => globalThis.dbAccess('readonly', 'passkeys', s => s.getAll()));
async function launch() {
  context = await chromium.launchPersistentContext(path.join(temporary, 'profile'), {
    executablePath: process.env.CHROME_PATH, headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  context.setDefaultTimeout(10000);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  id = new URL(worker.url()).host;
  fixture = await context.newPage();
  await fixture.goto(`chrome-extension://${id}/storage-test.html`);
  await fixture.evaluate(() => {
    globalThis.dbAccess = async (mode, name, operation) => {
      const db = await new Promise((resolve, reject) => {
        const r = indexedDB.open('NydiaDB', 4);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction(name, mode);
          const r = operation(tx.objectStore(name));
          tx.oncomplete = () => resolve(r?.result);
          tx.onabort = () => reject(tx.error);
        });
      } finally { db.close(); }
    };
    globalThis.restoreTestKey = async () => {
      // A fixed public test key, so the exact same key can be restored later.
      const root = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(37), 'HKDF', false, ['deriveKey']);
      await globalThis.testStore.setRootKey(root);
    };
  });
  menu = await context.newPage();
  await menu.setViewportSize({ width: 360, height: 700 });
}
async function openSettings() {
  await menu.goto(`chrome-extension://${id}/menu.html`);
  await menu.evaluate(() => {
    localStorage.setItem('nydiaOnboardingDone', 'true');
    localStorage.setItem('nydiaReopenRenterdSettings', 'true');
  });
  await menu.reload();
  await menu.locator('#settings-form').waitFor();
}
async function saveForm(value) {
  for (const [name, text] of Object.entries(value)) await menu.locator(`[name="${name}"]`).fill(String(text));
  await menu.getByRole('button', { name: 'Save', exact: true }).click();
  await menu.getByText('Settings saved successfully.', { exact: true }).waitFor();
}

// Real navigator.credentials -> injected code -> confirmation iframe ->
// production background. Neither authenticator nor messaging is mocked.
async function ceremony(operation, credentialId) {
  const rp = await context.newPage();
  await rp.goto(origin);
  const frameReady = rp.waitForEvent('framenavigated', { predicate: f => f.url() === `chrome-extension://${id}/popup.html` });
  await rp.evaluate(({ operation, credentialId }) => {
    const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const challenge = new Uint8Array(32).fill(operation === 'create' ? 11 : 12);
    const request = operation === 'create'
      ? navigator.credentials.create({ publicKey: {
        challenge, rp: { id: 'localhost', name: 'Local test' },
        user: { id: new Uint8Array([9]), name: 'Browser user', displayName: 'Browser user' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      } })
      : navigator.credentials.get({ publicKey: {
        challenge, rpId: 'localhost', allowCredentials: [{ type: 'public-key', id: decode(credentialId) }],
      } });
    request.then(value => { globalThis.result = value.toJSON(); }).catch(error => { globalThis.result = { error: error.message }; });
  }, { operation, credentialId });
  const frame = await frameReady;
  // The confirmation iframe lives inside a closed shadow root. Dispatch the
  // UI events in that frame directly; pointer/focus behavior is not under test.
  if (operation === 'get') await frame.locator('.nydia-popup-account-item').dispatchEvent('click');
  await frame.getByRole('button', { name: operation === 'create' ? 'Create passkey' : 'Use passkey', exact: true }).dispatchEvent('click');
  await rp.waitForFunction(() => globalThis.result !== undefined);
  const result = await rp.evaluate(() => globalThis.result);
  assert.equal(result.error, undefined);
  await rp.close();
  return result;
}
function verifyAssertion(result, credentialId, publicKey) {
  assert.equal(result.id, credentialId);
  const client = Buffer.from(result.response.clientDataJSON, 'base64url');
  assert.deepEqual(JSON.parse(client), { type: 'webauthn.get', challenge: Buffer.alloc(32, 12).toString('base64url'), origin, crossOrigin: false });
  const auth = Buffer.from(result.response.authenticatorData, 'base64url');
  assert.deepEqual(auth.subarray(0, 32), createHash('sha256').update('localhost').digest());
  const signed = Buffer.concat([auth, createHash('sha256').update(client).digest()]);
  const key = createPublicKey({ key: Buffer.from(publicKey, 'base64url'), format: 'der', type: 'spki' });
  assert.equal(verify('sha256', signed, key, Buffer.from(result.response.signature, 'base64url')), true);
}

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = `http://localhost:${server.address().port}`;
  settings = { serverAddress: 'localhost', serverPort: server.address().port, password: expectedPassword, bucketName: 'browser-test-bucket' };
  await launch();
  console.log(`Chrome ${context.browser().version()}; artifacts: ${temporary}`);
  await fixture.evaluate(() => globalThis.restoreTestKey());
  // Construct an old-format record independently, without the helpers being tested.
  const legacy = await fixture.evaluate(async () => {
    const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const { key: root } = await globalThis.dbAccess('readonly', 'settings', s => s.get('rootKey'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const seal = async (info, payload) => {
      const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) }, root, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(payload)));
      return { iv: encode(iv), data: encode(data) };
    };
    const record = {
      uniqueId: await globalThis.testStore.createUniqueId('localhost', 'Kg'), isSynced: false,
      metadata: await seal('metadata:v1', { rpId: 'localhost', userName: 'Legacy user', creationTime: 1 }),
      secret: await seal('secret:v1', { credentialId: 'Kg', userHandle: 'Bw', publicKeyAlgorithm: -7, privateKey: encode(await crypto.subtle.exportKey('pkcs8', pair.privateKey)) }),
    };
    await globalThis.dbAccess('readwrite', 'passkeys', s => s.put(record));
    return { record, publicKey: encode(await crypto.subtle.exportKey('spki', pair.publicKey)) };
  });
  assert.equal((await message({ type: 'getAllCredentialsMetadata' }))[0].userName, 'Legacy user');
  verifyAssertion(await ceremony('get', 'Kg'), 'Kg', legacy.publicKey);
  assert.deepEqual((await records())[0], legacy.record);
  passed('Existing passkey is read by production background and signs in through the confirmation UI');
  const created = await ceremony('create');
  verifyAssertion(await ceremony('get', created.id), created.id, created.response.publicKey);
  passed('New passkey registration and sign-in return a cryptographically valid assertion');
  await openSettings(); await saveForm(settings);
  const sealed = await row();
  assert.deepEqual(Object.keys(sealed).sort(), ['data', 'id', 'iv', 'version']);
  assert.ok(!JSON.stringify(sealed).includes(expectedPassword));
  assert.deepEqual(await message({ type: 'getSettings' }), settings);
  await menu.getByRole('button', { name: 'Test Connection', exact: true }).click();
  await menu.getByText('Connection successful.', { exact: true }).waitFor();
  passed('Settings Save and Test Connection work with encrypted storage');
  assert.equal((await message({ type: 'uploadToSia', uniqueId: legacy.record.uniqueId })).success, true);
  await fixture.evaluate(id => globalThis.dbAccess('readwrite', 'passkeys', s => s.delete(id)), legacy.record.uniqueId);
  assert.equal((await message({ type: 'syncFromSia' })).success, true);
  verifyAssertion(await ceremony('get', 'Kg'), 'Kg', legacy.publicKey);
  passed('Backup/Sync via the local renterd fixture restores a usable passkey');
  await context.close(); await launch(); await openSettings();
  assert.equal(await menu.locator('[name="password"]').inputValue(), expectedPassword);
  verifyAssertion(await ceremony('get', created.id), created.id, created.response.publicKey);
  passed('Settings and new passkeys survive a full browser restart');
  const before = await records();
  const good = await row(); await putRow({ ...good, data: 'A'.repeat(40) }); await openSettings();
  await menu.locator('.settings-warning').waitFor(); await putRow(good);
  await menu.getByRole('button', { name: 'Retry', exact: true }).click();
  await menu.waitForFunction(() => document.querySelector('[name="password"]')?.value === 'browser-test-password');
  await putRow({ ...good, data: 123 }); await openSettings(); await saveForm(settings);
  assert.deepEqual(await records(), before);
  passed('Retry and explicit replacement of damaged settings preserve passkeys');
  await putRow({ id: 'renterdSettings', ...settings }); await context.close(); await launch();
  await fixture.waitForFunction(async () => (await globalThis.dbAccess('readonly', 'settings', s => s.get('renterdSettings')))?.version === 1);
  assert.deepEqual(await message({ type: 'getSettings' }), settings);
  assert.deepEqual(await records(), before);
  passed('Startup migrates old plaintext settings without changing passkeys');
  await fixture.evaluate(value => globalThis.testStore.saveServerProtocol(value, 'https'), settings);
  await fixture.evaluate(value => globalThis.testStore.saveServerProtocol(value, 'http'), settings);
  assert.equal((await message({ type: 'getSettings' })).serverProtocol, 'https');
  passed('A late detection cannot overwrite an already saved protocol');
  console.log(`${checks} browser checks passed`);
} catch (error) {
  console.error(error);
  if (menu && !menu.isClosed()) await menu.screenshot({ path: path.join(temporary, 'failure.png') }).catch(() => {});
  process.exitCode = 1;
} finally {
  await context?.close();
  server.close();
}
