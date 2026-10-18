import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import Module from 'node:module';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const backgroundPath = fileURLToPath(new URL('../.test-build/background.js', import.meta.url));
const require = createRequire(import.meta.url);

let messageListener;
let rootKeyCalls = 0;
const calls = {
  create: [],
  get: [],
  available: [],
};

const browserMock = {
  runtime: {
    onMessage: {
      addListener(listener) {
        messageListener = listener;
      },
    },
  },
};

const authenticatorMock = {
  async createCredential(options) {
    calls.create.push(options);
    return { operation: 'create' };
  },
  async handleGetAssertion(options, selectedUniqueId) {
    calls.get.push({ options, selectedUniqueId });
    return { operation: 'get' };
  },
  async getAvailableCredentials(rpId, allowCredentialIds) {
    calls.available.push({ rpId, allowCredentialIds });
    return [];
  },
};

const storeMock = {
  async getRootKeyIfAvailable() {
    rootKeyCalls += 1;
    return true;
  },
  async getEncryptedRecord() {
    throw new Error('Unexpected getEncryptedRecord call');
  },
  async getSettings() {
    throw new Error('Unexpected getSettings call');
  },
  async handleMessageInBackground() {
    throw new Error('Unexpected handleMessageInBackground call');
  },
  async saveEncryptedRecord() {
    throw new Error('Unexpected saveEncryptedRecord call');
  },
  async setRootKey() {
    throw new Error('Unexpected setRootKey call');
  },
};

const siaMock = {
  async downloadPasskeyFromRenterd() {
    throw new Error('Unexpected downloadPasskeyFromRenterd call');
  },
  async listPasskeysFromRenterd() {
    throw new Error('Unexpected listPasskeysFromRenterd call');
  },
  async uploadPasskeyDirect() {
    throw new Error('Unexpected uploadPasskeyDirect call');
  },
};

const loggerMock = {
  logDebug() {},
  logError() {},
  logInfo() {},
};

const backgroundMocks = new Map([
  ['browser-api', browserMock],
  ['./authenticator', authenticatorMock],
  ['./logger', loggerMock],
  ['./sia', siaMock],
  ['./store', storeMock],
]);

// Load the real compiled background module while replacing only its external
// boundaries. The registered listener still executes the production router,
// RP-ID helpers and option converters.
const originalLoad = Module._load;
try {
  Module._load = function loadWithBackgroundMocks(request, parent, isMain) {
    if (parent?.filename === backgroundPath && backgroundMocks.has(request)) {
      return backgroundMocks.get(request);
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  require(backgroundPath);
} finally {
  Module._load = originalLoad;
}

assert.equal(typeof messageListener, 'function', 'background listener was not registered');

// Ignore the bootstrap root-key probe; each test counts only operation-time reads.
rootKeyCalls = 0;

function sender(origin) {
  return { origin, frameId: 0, tab: {} };
}

function resetCalls() {
  rootKeyCalls = 0;
  calls.create.length = 0;
  calls.get.length = 0;
  calls.available.length = 0;
}

test('background listener passes canonical RP IDs and trusted origin to its boundaries', async () => {
  resetCalls();

  assert.deepEqual(
    await messageListener(
      { type: 'validateRpId', rpId: 'EXAMPLE.COM' },
      sender('https://login.example.com'),
    ),
    { valid: true },
  );

  const createResponse = await messageListener(
    {
      type: 'createCredential',
      options: {
        origin: 'https://forged.example',
        publicKey: {
          rp: { id: 'EXAMPLE.COM', name: 'Example' },
          user: { id: 'AQ', name: 'person@example.com' },
          challenge: 'AQ',
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
    },
    sender('https://login.example.com:8443'),
  );

  assert.deepEqual(createResponse, { operation: 'create' });
  assert.equal(rootKeyCalls, 1);
  assert.equal(calls.create.length, 1);
  assert.equal(calls.create[0].origin, 'https://login.example.com:8443');
  assert.equal(calls.create[0].publicKey.rp.id, 'example.com');
  assert.equal(calls.create[0].publicKey.rpId, 'example.com');

  const getResponse = await messageListener(
    {
      type: 'handleGetAssertion',
      options: {
        origin: 'https://forged.example',
        publicKey: {
          challenge: 'AQ',
          rpId: 'bücher.example',
        },
      },
      selectedUniqueId: 'credential-1',
    },
    sender('https://xn--bcher-kva.example'),
  );

  assert.deepEqual(getResponse, { operation: 'get' });
  assert.equal(calls.get.length, 1);
  assert.equal(calls.get[0].selectedUniqueId, 'credential-1');
  assert.equal(calls.get[0].options.origin, 'https://xn--bcher-kva.example');
  assert.equal(calls.get[0].options.publicKey.rpId, 'xn--bcher-kva.example');

  await messageListener(
    {
      type: 'getAvailableCredentials',
      rpId: 'EXAMPLE.COM',
      allowCredentialIds: ['credential-1'],
    },
    sender('https://login.example.com'),
  );

  assert.equal(rootKeyCalls, 2);
  assert.deepEqual(calls.available, [
    { rpId: 'example.com', allowCredentialIds: ['credential-1'] },
  ]);
});

test('background listener blocks invalid RP IDs before storage and authenticator access', async () => {
  resetCalls();

  const cases = [
    {
      message: { type: 'validateRpId', rpId: 'bank.example' },
    },
    {
      message: {
        type: 'createCredential',
        options: {
          publicKey: {
            rp: { id: 'bank.example', name: 'Bank' },
            user: { id: 'AQ', name: 'person@example.com' },
            challenge: 'AQ',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
    },
    {
      message: {
        type: 'handleGetAssertion',
        options: {
          publicKey: {
            challenge: 'AQ',
            rpId: 'bank.example',
          },
        },
        selectedUniqueId: 'credential-1',
      },
    },
    {
      message: {
        type: 'getAvailableCredentials',
        rpId: 'bank.example',
      },
    },
  ];

  for (const { message } of cases) {
    const response = await messageListener(message, sender('https://login.example.com'));
    assert.equal(response.errorName, 'SecurityError');
    assert.equal(response.error, 'rpId is not valid for the requesting origin');
  }

  assert.equal(rootKeyCalls, 0);
  assert.equal(calls.create.length, 0);
  assert.equal(calls.get.length, 0);
  assert.equal(calls.available.length, 0);
});

// Exercise the real listener with structured-clone-compatible malformed input.
// Neither sender rejection nor shape rejection may probe local keys/settings.
for (const operation of ['createCredential', 'handleGetAssertion']) {
  for (const trusted of [false, true]) {
    const title = trusted
      ? `${operation}: rejects malformed publicKey from a trusted sender`
      : `${operation}: rejects an untrusted sender before validating publicKey`;
    test(title, async () => {
      for (const publicKey of [undefined, null, '', 'bad', 1, true, [], ['bad']]) {
        resetCalls();
        const response = await messageListener(
          { type: operation, options: { publicKey }, selectedUniqueId: 'credential-1' },
          sender(trusted ? 'https://example.com' : 'null'),
        );
        assert.deepEqual(response, trusted
          ? { error: 'Invalid options: publicKey is required' }
          : { error: 'Untrusted WebAuthn sender', errorName: 'SecurityError' });
        assert.equal(rootKeyCalls, 0);

        assert.deepEqual(calls, { create: [], get: [], available: [] });
      }
    });
  }
}

test('all WebAuthn routes reject untrusted senders before local state', async () => {
  const messages = [
    { type: 'validateRpId', rpId: 'example.com' },
    { type: 'createCredential', options: { publicKey: {} } },
    { type: 'handleGetAssertion', options: { publicKey: {} } },
    { type: 'getAvailableCredentials', rpId: 'example.com' },
  ];
  const untrustedSenders = [
    null,
    {},
    { url: 'https://example.com', frameId: 0, tab: {} },
    { origin: 'null', url: 'https://example.com', frameId: 0, tab: {} },
    { origin: 'https://example.com', frameId: 1, tab: {} },
    { origin: 'https://example.com', frameId: 0 },
  ];
  for (const untrustedSender of untrustedSenders) {
    for (const message of messages) {
      resetCalls();
      assert.deepEqual(await messageListener(message, untrustedSender), {
        error: 'Untrusted WebAuthn sender', errorName: 'SecurityError',
      });
      assert.equal(rootKeyCalls, 0);

      assert.deepEqual(calls, { create: [], get: [], available: [] });
    }
  }
});

test('creation and assertion without an RP ID use the trusted caller domain', async () => {
  resetCalls();
  const trustedSender = sender('https://LOGIN.Example.com:8443');
  assert.deepEqual(await messageListener({
    type: 'createCredential',
    options: {
      origin: 'https://forged.example',
      publicKey: {
        rp: { name: 'Example' }, user: { id: 'AQ', name: 'alice' },
        challenge: 'AQ', pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    },
  }, trustedSender), { operation: 'create' });
  assert.deepEqual(await messageListener({
    type: 'handleGetAssertion', selectedUniqueId: 'credential-1',
    options: { origin: 'https://forged.example', publicKey: { challenge: 'AQ' } },
  }, trustedSender), { operation: 'get' });
  assert.equal(calls.create[0].publicKey.rp.id, 'login.example.com');
  assert.equal(calls.get[0].options.publicKey.rpId, 'login.example.com');
  assert.equal(calls.create[0].origin, 'https://login.example.com:8443');
  assert.equal(calls.get[0].options.origin, 'https://login.example.com:8443');
});

// The router must keep a DOMException's name: an excludeCredentials match has to
// reach the page as InvalidStateError, not as a generic failure.
test('background listener keeps the DOMException name of an authenticator error', async () => {
  resetCalls();
  const createCredential = authenticatorMock.createCredential;
  authenticatorMock.createCredential = async () => {
    throw new DOMException('A passkey for this account already exists.', 'InvalidStateError');
  };
  try {
    const response = await messageListener(
      {
        type: 'createCredential',
        options: {
          publicKey: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'AQ', name: 'person@example.com' },
            challenge: 'AQ',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
      sender('https://login.example.com'),
    );
    assert.deepEqual(response, {
      error: 'A passkey for this account already exists.',
      errorName: 'InvalidStateError',
    });
  } finally {
    authenticatorMock.createCredential = createCredential;
  }
});

// A valid request from a trusted page still needs a vault that is set up:
// without a root key, creation and discovery stop before the authenticator.
test('background listener stops valid requests without a root key', async () => {
  const getRootKeyIfAvailable = storeMock.getRootKeyIfAvailable;
  storeMock.getRootKeyIfAvailable = async () => {
    rootKeyCalls += 1;
    return null;
  };
  try {
    resetCalls();
    const create = await messageListener(
      {
        type: 'createCredential',
        options: {
          publicKey: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'AQ', name: 'person@example.com' },
            challenge: 'AQ',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
      sender('https://login.example.com'),
    );
    const available = await messageListener(
      { type: 'getAvailableCredentials', rpId: 'example.com' },
      sender('https://login.example.com'),
    );

    assert.deepEqual(create, { error: 'rootKeyMissing' });
    assert.deepEqual(available, { error: 'rootKeyMissing' });
    assert.equal(rootKeyCalls, 2);
    assert.deepEqual(calls, { create: [], get: [], available: [] });
  } finally {
    storeMock.getRootKeyIfAvailable = getRootKeyIfAvailable;
  }
});
