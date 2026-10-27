import assert from 'node:assert/strict';
import { test } from 'node:test';

import { holdingCrypto, settingsVault } from './helpers/settingsVault.mjs';

const SETTINGS = {
  serverAddress: 'private-renterd.example', serverPort: 9980,
  password: 'long-server-password', bucketName: 'private-backup-bucket', serverProtocol: 'https',
};
const save = (store, settings = SETTINGS) => store.handleMessageInBackground({ type: 'saveSettings', settings });

test('all renterd fields are encrypted, each save has a new IV, and another context can open them', async () => {
  const vault = await settingsVault();
  assert.equal((await save(vault.store, { ...SETTINGS, unexpected: 'must-not-be-saved' })).status, 'ok');
  assert.deepEqual(Object.keys(vault.record()).sort(), ['data', 'id', 'iv', 'version']);
  assert.equal(vault.record().version, 1);
  for (const field of ['serverAddress', 'serverPort', 'password', 'bucketName', 'serverProtocol', 'unexpected']) {
    assert.ok(!(field in vault.record()));
  }
  for (const value of [SETTINGS.password, SETTINGS.serverAddress, SETTINGS.bucketName, 'must-not-be-saved']) {
    assert.ok(!JSON.stringify(vault.record()).includes(value));
  }
  assert.deepEqual(await vault.saved(), SETTINGS);
  assert.deepEqual({ ...await vault.reload().getSettings() }, SETTINGS);
  const first = vault.record();
  await save(vault.store);
  assert.notEqual(vault.record().iv, first.iv);
  assert.notEqual(vault.record().data, first.data);
});

test('missing settings are distinct from a missing key, and no plaintext save is allowed', async () => {
  const empty = await settingsVault(undefined, { root: false });
  assert.equal(await empty.store.getSettings(), null);
  assert.equal((await save(empty.store)).error, 'rootKeyMissing');
  assert.equal(empty.record(), undefined);

  const vault = await settingsVault(SETTINGS, { plaintext: true, root: false });
  const before = structuredClone(vault.record());
  await assert.rejects(vault.store.getSettings(), /rootKeyMissing/);
  await assert.rejects(vault.store.sealPlaintextSettings(), /rootKeyMissing/);
  assert.deepEqual(vault.record(), before);
  await vault.store.setRootKey(vault.rootKey);
  await vault.store.sealPlaintextSettings();
  assert.deepEqual(await vault.saved(), SETTINGS);
});

test('plaintext settings migrate atomically under the same ID, without changing passkeys or the root key', async () => {
  const vault = await settingsVault(SETTINGS, { plaintext: true });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const uniqueId = await vault.store.savePrivateKey(new Uint8Array([1]), 'example.com', pair.privateKey, new Uint8Array([2]), -7, 'User');
  const passkeys = vault.indexedDB.entries('NydiaDB', 'passkeys');
  const before = structuredClone(passkeys.get(uniqueId));
  const root = vault.settings.get('rootKey').key;
  assert.deepEqual({ ...await vault.store.getSettings() }, SETTINGS);
  assert.deepEqual(await vault.saved(), SETTINGS);
  assert.deepEqual([...vault.settings.keys()].sort(), ['renterdSettings', 'rootKey']);
  assert.equal(vault.settings.get('rootKey').key, root);
  assert.deepEqual(passkeys.get(uniqueId), before);
  assert.equal((await vault.store.getAllCredentialsMetadata())[0].rpId, 'example.com');
  assert.equal((await vault.store.openSecret(uniqueId)).credentialId, 'AQ');
});

test('a failed migration reports the error and retains the old data for a retry', async () => {
  for (const failure of ['failWrites', 'failCommit']) {
    const vault = await settingsVault(SETTINGS, { plaintext: true });
    const before = structuredClone(vault.record());
    vault.database[failure] = true;
    const response = await vault.store.handleMessageInBackground({ type: 'getSettings' });
    assert.match(response.error, /Disk full|Commit failed/);
    assert.deepEqual(vault.record(), before);
    vault.database[failure] = false;
    assert.deepEqual({ ...await vault.store.getSettings() }, SETTINGS);
    assert.deepEqual(await vault.saved(), SETTINGS);
  }
});

test('damaged ciphertext, unsupported versions and malformed envelopes never become empty or plaintext settings', async () => {
  const mutations = [
    (record) => { record.data = 'A'.repeat(40); },
    (record) => { record.iv = 'AA'; },
    (record) => { record.iv = 'B'.repeat(16); },
    (record) => { record.version = 2; },
    (record) => { delete record.data; Object.assign(record, SETTINGS); },
    (record) => { delete record.version; Object.assign(record, SETTINGS); },
  ];
  for (const mutate of mutations) {
    const vault = await settingsVault(SETTINGS);
    mutate(vault.record());
    const before = structuredClone(vault.record());
    const response = await vault.store.handleMessageInBackground({ type: 'getSettings' });
    assert.match(response.error, /decrypt|format/);
    assert.deepEqual(vault.record(), before);
  }
});

test('a wrong key or an invalid authenticated payload reports an error without replacing the record', async () => {
  const vault = await settingsVault(SETTINGS);
  const wrongRoot = await crypto.subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveKey']);
  await vault.store.setRootKey(wrongRoot);
  const before = structuredClone(vault.record());
  await assert.rejects(vault.store.getSettings(), /Unable to decrypt/);
  assert.deepEqual(vault.record(), before);

  for (const malformed of [null, {}, { ...SETTINGS, serverPort: '9980' }, { ...SETTINGS, serverProtocol: 'ftp' }]) {
    const other = await settingsVault();
    other.settings.set('renterdSettings', await other.seal(malformed));
    await assert.rejects(other.store.getSettings(), /Unable to decrypt/);
  }
  const invalidLegacy = await settingsVault({ ...SETTINGS, password: 123 }, { plaintext: true });
  await assert.rejects(invalidLegacy.store.getSettings(), /format/);
});

test('migration does not overwrite a newer save and returns the newer settings', async () => {
  const held = holdingCrypto('encrypt');
  const vault = await settingsVault(SETTINGS, { plaintext: true, crypto: held.crypto });
  const reading = vault.store.getSettings();
  await held.reached;
  const newer = { ...SETTINGS, password: 'corrected' };
  assert.equal((await save(vault.store, newer)).status, 'ok');
  const committed = structuredClone(vault.record());
  held.release();
  assert.deepEqual({ ...await reading }, newer);
  assert.deepEqual(vault.record(), committed);
});

test('migration retries if another context changes the plaintext record during encryption', async () => {
  const held = holdingCrypto('encrypt');
  const vault = await settingsVault(SETTINGS, { plaintext: true, crypto: held.crypto });
  const reading = vault.store.getSettings();
  await held.reached;
  const newer = { ...SETTINGS, bucketName: 'new-bucket' };
  vault.settings.set('renterdSettings', { id: 'renterdSettings', ...newer });
  held.release();
  assert.deepEqual({ ...await reading }, newer);
  assert.deepEqual(await vault.saved(), newer);
});

test('protocol detection keeps the latest bucket but cannot publish a result for an old server or password', async () => {
  const vault = await settingsVault({ ...SETTINGS, serverProtocol: undefined });
  for (const changed of [{ serverAddress: 'other.example' }, { serverPort: 443 }, { password: 'corrected' }]) {
    const newer = { ...SETTINGS, ...changed, serverProtocol: undefined };
    await save(vault.store, newer);
    const before = structuredClone(vault.record());
    await vault.store.saveServerProtocol(SETTINGS, 'http');
    assert.deepEqual(vault.record(), before);
  }
  await save(vault.store, { ...SETTINGS, bucketName: 'new-bucket', serverProtocol: undefined });
  await vault.store.saveServerProtocol(SETTINGS, 'http');
  assert.deepEqual(await vault.saved(), { ...SETTINGS, bucketName: 'new-bucket', serverProtocol: 'http' });
});

test('a protocol already saved is not replaced by a later detection', async () => {
  const vault = await settingsVault(SETTINGS);
  const before = structuredClone(vault.record());
  await vault.store.saveServerProtocol(SETTINGS, 'http');
  assert.deepEqual(vault.record(), before);
  assert.equal((await vault.saved()).serverProtocol, 'https');
});

test('a save made during protocol decryption or encryption wins without losing its fields', async () => {
  for (const method of ['decrypt', 'encrypt']) {
    const held = holdingCrypto(method);
    // No protocol yet, so only the check against the save keeps the record.
    const vault = await settingsVault({ ...SETTINGS, serverProtocol: undefined }, { crypto: held.crypto });
    const detecting = vault.store.saveServerProtocol(SETTINGS, 'http');
    await held.reached;
    const newer = { ...SETTINGS, password: 'corrected', bucketName: 'new-bucket' };
    assert.equal((await save(vault.store, newer)).status, 'ok');
    const before = structuredClone(vault.record());
    held.release();
    await detecting;
    assert.deepEqual(vault.record(), before);
    assert.deepEqual(await vault.saved(), newer);
  }
});
