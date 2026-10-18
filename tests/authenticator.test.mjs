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
      // An old record can still carry a non-zero counter; assertions must ignore it.
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
  assertAttestationObject(created, alg, publicKey);
  return { uniqueId: writes.at(-1), credentialId: created.rawId, publicKey };
}

// Minimal CBOR decoder for the attestation and COSE fixtures, independent of
// src/cbor.ts. Unsupported CBOR types and length encodings throw.
function decodeCbor(bytes, start = 0) {
  let offset = start;
  const head = bytes[offset++];
  const major = head >> 5;
  const info = head & 0x1f;
  let length = info;
  if (info === 24) length = bytes[offset++];
  else if (info === 25) { length = bytes.readUInt16BE(offset); offset += 2; }
  else if (info === 26) { length = bytes.readUInt32BE(offset); offset += 4; }
  else if (info > 26) throw new Error(`unsupported CBOR length encoding ${info}`);

  switch (major) {
    case 0: return { value: length, offset };
    case 1: return { value: -1 - length, offset };
    case 2: return { value: bytes.subarray(offset, offset + length), offset: offset + length };
    case 3: return { value: bytes.subarray(offset, offset + length).toString('utf8'), offset: offset + length };
    case 4: {
      const items = [];
      for (let i = 0; i < length; i++) ({ value: items[i], offset } = decodeCbor(bytes, offset));
      return { value: items, offset };
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < length; i++) {
        let key, value;
        ({ value: key, offset } = decodeCbor(bytes, offset));
        ({ value, offset } = decodeCbor(bytes, offset));
        map.set(key, value);
      }
      return { value: map, offset };
    }
    default: throw new Error(`unsupported CBOR major type ${major}`);
  }
}

function coseToJwk(cose, alg) {
  const b64 = (key) => Buffer.from(cose.get(key)).toString('base64url');
  assert.equal(cose.get(3), alg, 'COSE key must carry the requested algorithm');
  switch (alg) {
    case -7:
      assert.equal(cose.get(1), 2, 'ES256 COSE key type must be EC2');
      assert.equal(cose.get(-1), 1, 'ES256 COSE curve must be P-256');
      return { kty: 'EC', crv: 'P-256', x: b64(-2), y: b64(-3) };
    case -257:
      assert.equal(cose.get(1), 3, 'RS256 COSE key type must be RSA');
      return { kty: 'RSA', n: b64(-1), e: b64(-2) };
    case -8:
      assert.equal(cose.get(1), 1, 'Ed25519 COSE key type must be OKP');
      assert.equal(cose.get(-1), 6, 'Ed25519 COSE curve must be Ed25519');
      return { kty: 'OKP', crv: 'Ed25519', x: b64(-2) };
    default:
      throw new Error(`unexpected algorithm ${alg}`);
  }
}

// The relying party reads the attestation object, not publicKeyDER. Decode it
// independently and check that it carries the same key and authenticator data.
function assertAttestationObject(created, alg, publicKey) {
  const attestationBytes = Buffer.from(created.response.attestationObject, 'base64url');
  const { value: attestation, offset: end } = decodeCbor(attestationBytes);
  assert.equal(end, attestationBytes.length, 'attestationObject must have no trailing bytes');
  assert.deepEqual([...attestation.keys()], ['fmt', 'attStmt', 'authData']);
  assert.equal(attestation.get('fmt'), 'none');
  assert.equal(attestation.get('attStmt').size, 0, 'a "none" attestation has an empty attStmt');

  const authData = attestation.get('authData');
  assert.deepEqual(
    authData,
    Buffer.from(created.response.authenticatorData, 'base64url'),
    'authData inside attestationObject must equal the returned authenticatorData',
  );
  assert.equal(authData[32] & 0x40, 0x40, 'attested credential data flag must be set');
  assert.equal(authData[32] & 0x80, 0, 'no extension data is included');

  const credentialIdLength = authData.readUInt16BE(53);
  const credentialId = authData.subarray(55, 55 + credentialIdLength);
  assert.equal(credentialId.toString('base64url'), created.rawId, 'credentialId must match rawId');

  const { value: cose, offset: coseEnd } = decodeCbor(authData, 55 + credentialIdLength);
  assert.equal(coseEnd, authData.length, 'the COSE key must end authData');
  const coseKey = createPublicKey({ key: coseToJwk(cose, alg), format: 'jwk' });
  assert.deepEqual(
    coseKey.export({ type: 'spki', format: 'der' }),
    publicKey.export({ type: 'spki', format: 'der' }),
    'the COSE key must be the same public key as publicKeyDER',
  );
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

test('a request with no supported algorithm is refused with NotSupportedError and writes nothing', async () => {
  const writesBefore = writes.length;
  await assert.rejects(
    create(-35),
    (error) => error instanceof DOMException && error.name === 'NotSupportedError',
  );
  assert.equal(writes.length, writesBefore, 'a refused registration wrote to the store');
});

// A credential is scoped to the RP it was created for. Without allowCredentials
// the request names no credential, so the authenticator itself must refuse a
// record that belongs to another RP instead of signing for the requested one.
test('get: refuses a credential created for another RP', async () => {
  const challenge = randomChallenge();
  await authenticator.createCredential({
    publicKey: {
      rp: { id: 'foreign.example', name: 'Foreign' },
      rpId: 'foreign.example',
      user: { id: new Uint8Array([7]), name: 'person@foreign.example', displayName: 'Person' },
      challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    },
    origin: 'https://foreign.example',
  });
  const foreignUniqueId = writes.at(-1);

  await assert.rejects(
    authenticator.handleGetAssertion(
      { publicKey: { challenge: randomChallenge(), rpId: RP_ID }, origin: ORIGIN },
      foreignUniqueId,
    ),
    (error) => error instanceof DOMException && error.name === 'NotAllowedError',
  );
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
