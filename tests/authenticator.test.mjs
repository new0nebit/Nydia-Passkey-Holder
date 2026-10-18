import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { createRequire } from 'node:module';
import Module from 'node:module';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const authenticatorPath = fileURLToPath(new URL('../.test-build/authenticator.js', import.meta.url));
const require = createRequire(import.meta.url);

// The store is replaced by an in-memory record per credential. Only the calls
// the authenticator makes today are provided: a counter write reintroduced on
// the assertion path would have nothing to call and fail the test.
const records = new Map();
const writes = [];

function encode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

const storeMock = {
  async createUniqueId(rpId, credentialId) {
    return `${rpId}:${credentialId}`;
  },
  async getEncryptedRecord(uniqueId) {
    return records.get(uniqueId) ?? null;
  },
  async getAllCredentialsMetadata() {
    return [];
  },
  async getCredentialsMetadataByUniqueIds() {
    return [];
  },
  async savePrivateKey(credentialId, rpId, privateKey, userId, publicKeyAlgorithm) {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    const uniqueId = `${rpId}:${encode(credentialId)}`;
    writes.push(uniqueId);
    records.set(uniqueId, {
      credentialId: encode(credentialId),
      userHandle: encode(userId),
      publicKeyAlgorithm,
      privateKey: encode(new Uint8Array(pkcs8)),
      // A record written before Commit 0 still carries its old counter.
      counter: 42,
    });
    return uniqueId;
  },
  async openSecret(uniqueId) {
    const record = records.get(uniqueId);
    if (!record) throw new Error('Credential not found');
    return record;
  },
};

const originalLoad = Module._load;
let authenticator;
try {
  Module._load = function loadWithStoreMock(request, parent, isMain) {
    if (parent?.filename === authenticatorPath) {
      if (request === './store') return storeMock;
      if (request === './logger') return { logDebug() {}, logError() {}, logInfo() {} };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  authenticator = require(authenticatorPath);
} finally {
  Module._load = originalLoad;
}

const ORIGIN = 'https://login.example.com';
const RP_ID = 'example.com';
const RP_ID_HASH = createHash('sha256').update(RP_ID).digest();

function randomChallenge() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// A signature only proves who signed. The response must also describe this
// request: a valid signature over the wrong challenge, origin or RP ID is still
// rejected by the relying party.
function assertCeremony(response, type, challenge) {
  const clientData = JSON.parse(Buffer.from(response.clientDataJSON, 'base64url').toString('utf8'));
  assert.equal(clientData.type, type);
  assert.equal(clientData.challenge, Buffer.from(challenge).toString('base64url'));
  assert.equal(clientData.origin, ORIGIN);

  const authenticatorData = Buffer.from(response.authenticatorData, 'base64url');
  assert.deepEqual(authenticatorData.subarray(0, 32), RP_ID_HASH, 'rpIdHash must hash the RP ID');
  assert.equal(authenticatorData[32] & 0x01, 0x01, 'user presence flag must be set');
  assert.equal(authenticatorData.readUInt32BE(33), 0, 'signCount must be 0');
}

async function create(alg, excludeCredentials) {
  const challenge = randomChallenge();
  const created = await authenticator.createCredential({
    publicKey: {
      rp: { id: RP_ID, name: 'Example' },
      rpId: RP_ID,
      user: { id: new Uint8Array([1, 2, 3]), name: 'person@example.com', displayName: 'Person' },
      challenge,
      pubKeyCredParams: [{ type: 'public-key', alg }],
      ...(excludeCredentials && { excludeCredentials }),
    },
    origin: ORIGIN,
  });
  assertCeremony(created.response, 'webauthn.create', challenge);
  return created;
}

async function register(alg) {
  const created = await create(alg);
  assert.equal(created.response.publicKeyAlgorithm, alg, 'the requested algorithm must be selected');
  const publicKey = createPublicKey({
    key: Buffer.from(created.response.publicKeyDER, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  const expectedKeyType = new Map([[-7, 'ec'], [-257, 'rsa'], [-8, 'ed25519']]).get(alg);
  assert.equal(publicKey.asymmetricKeyType, expectedKeyType, 'SPKI must use the requested algorithm');
  return { uniqueId: writes.at(-1), credentialId: created.rawId, publicKey };
}

async function sign(uniqueId, allowCredentials) {
  const challenge = randomChallenge();
  const assertion = await authenticator.handleGetAssertion(
    {
      publicKey: { challenge, rpId: RP_ID, ...(allowCredentials && { allowCredentials }) },
      origin: ORIGIN,
    },
    uniqueId,
  );
  assertCeremony(assertion.response, 'webauthn.get', challenge);
  return assertion;
}

function verifies(alg, publicKey, response) {
  const authenticatorData = Buffer.from(response.authenticatorData, 'base64url');
  const clientDataHash = createHash('sha256')
    .update(Buffer.from(response.clientDataJSON, 'base64url'))
    .digest();
  const signed = Buffer.concat([authenticatorData, clientDataHash]);
  const signature = Buffer.from(response.signature, 'base64url');
  return verify(alg === -8 ? null : 'sha256', signed, publicKey, signature);
}

function credentialIdBytes(credentialId) {
  return new Uint8Array(Buffer.from(credentialId, 'base64url'));
}

for (const [alg, name] of [
  [-7, 'ES256'],
  [-257, 'RS256'],
  [-8, 'Ed25519'],
]) {
  test(`${name} assertions verify, report signCount 0 and write nothing`, async () => {
    const { uniqueId, publicKey } = await register(alg);
    const writesAfterRegistration = writes.length;

    for (let i = 0; i < 3; i++) {
      const assertion = await sign(uniqueId);
      assert.ok(verifies(alg, publicKey, assertion.response), `${name} signature ${i} rejected`);
    }

    assert.equal(writes.length, writesAfterRegistration, 'an assertion wrote to the store');
  });
}

test('excludeCredentials: refuses an existing credential and allows an unknown one', async () => {
  const { credentialId } = await register(-7);
  const writesBefore = writes.length;

  await assert.rejects(
    create(-7, [{ type: 'public-key', id: credentialIdBytes(credentialId) }]),
    (error) => error instanceof DOMException && error.name === 'InvalidStateError',
  );
  assert.equal(writes.length, writesBefore, 'a refused registration wrote to the store');

  await create(-7, [{ type: 'public-key', id: randomChallenge() }]);
  assert.equal(writes.length, writesBefore + 1, 'an unknown excluded credential blocked registration');
});

test('allowCredentials accepts a listed credential and refuses an unlisted one', async () => {
  const listed = await register(-7);
  const other = await register(-7);

  await sign(listed.uniqueId, [{ type: 'public-key', id: credentialIdBytes(listed.credentialId) }]);
  await assert.rejects(
    sign(listed.uniqueId, [{ type: 'public-key', id: credentialIdBytes(other.credentialId) }]),
    (error) => error instanceof DOMException && error.name === 'NotAllowedError',
  );
});
