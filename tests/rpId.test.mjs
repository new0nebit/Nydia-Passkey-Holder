import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalRpIdForOrigin, getWebAuthnSenderOrigin } from '../.test-build/utils/rpId.js';

const validCases = [
  ['https://login.example.com', 'login.example.com'],
  ['https://login.example.com', 'example.com'],
  ['https://login.example.com:8443', 'example.com'],
  ['https://example.co.uk', 'example.co.uk'],
  ['https://foo.github.io', 'foo.github.io'],
  ['https://localhost', 'localhost'],
  ['https://xn--caf-dma.example', 'xn--caf-dma.example'],
  ['https://xn--bcher-kva.example', 'bücher.example'],
  ['https://EXAMPLE.com', 'EXAMPLE.COM'],
];

const invalidCases = [
  ['https://login.example.com', 'bank.example'],
  ['https://evilaccounts.example.com', 'accounts.example.com'],
  ['https://login.example.com', 'com'],
  ['https://example.com', 'm.example.com'],
  ['https://example.co.uk', 'co.uk'],
  ['https://foo.github.io', 'github.io'],
  ['https://x.s3.amazonaws.com', 's3.amazonaws.com'],
  ['https://x.s3.amazonaws.com', 'amazonaws.com'],
  ['https://www.example.compute.amazonaws.com', 'example.compute.amazonaws.com'],
  ['https://login.example.com', ''],
  ['https://login.example.com', null],
  ['https://login.example.com', 'example.com:443'],
  ['https://login.example.com', 'example.com/path'],
  ['https://login.example.com', 'user@example.com'],
  ['https://127.0.0.1', '127.0.0.1'],
  ['https://example.com.', 'example.com.'],
];

test('accepts equal domains and registrable parent RP IDs', () => {
  for (const [origin, rpId] of validCases) {
    assert.notEqual(
      canonicalRpIdForOrigin(rpId, origin),
      null,
      `expected ${String(rpId)} to be valid for ${origin}`,
    );
  }
});

test('rejects unrelated, malformed, public-suffix and private-suffix RP IDs', () => {
  for (const [origin, rpId] of invalidCases) {
    assert.equal(
      canonicalRpIdForOrigin(rpId, origin),
      null,
      `expected ${String(rpId)} to be invalid for ${origin}`,
    );
  }
});

// The returned value is hashed into authenticatorData and used as a storage
// key, so an accepted RP ID must come back in one canonical spelling.
test('returns the canonical ASCII RP ID rather than the page spelling', () => {
  assert.equal(canonicalRpIdForOrigin('EXAMPLE.COM', 'https://example.com'), 'example.com');
  assert.equal(canonicalRpIdForOrigin('Example.Com', 'https://login.example.com'), 'example.com');
  assert.equal(
    canonicalRpIdForOrigin('bücher.example', 'https://xn--bcher-kva.example'),
    'xn--bcher-kva.example',
  );
  assert.equal(
    canonicalRpIdForOrigin('xn--bcher-kva.example', 'https://xn--bcher-kva.example'),
    'xn--bcher-kva.example',
  );
});

// An operation that supplies no rp.id/rpId defaults to the caller host, and
// an origin that cannot name an RP still has no RP ID to default to.
test('defaults the RP ID to the canonical caller host', () => {
  assert.equal(canonicalRpIdForOrigin(undefined, 'https://LOGIN.Example.com'), 'login.example.com');
  assert.equal(canonicalRpIdForOrigin(undefined, 'https://example.co.uk'), 'example.co.uk');
  assert.equal(canonicalRpIdForOrigin(undefined, 'https://127.0.0.1'), null);
  assert.equal(
    canonicalRpIdForOrigin(undefined, 'moz-extension://extension-id/page.html'),
    null,
  );
});

test('uses the sender origin and requires a top-frame tab sender', () => {
  assert.equal(
    getWebAuthnSenderOrigin({
      origin: 'https://login.example.com',
      url: 'https://ignored.example/path',
      frameId: 0,
      tab: {},
    }),
    'https://login.example.com',
  );
  assert.equal(
    getWebAuthnSenderOrigin({
      origin: 'https://login.example.com',
      frameId: 1,
      tab: {},
    }),
    null,
  );
  assert.equal(
    getWebAuthnSenderOrigin({
      origin: 'https://login.example.com',
      frameId: 0,
    }),
    null,
  );
});

test('rejects opaque origins without falling back to sender URL', () => {
  assert.equal(
    getWebAuthnSenderOrigin({
      origin: 'null',
      url: 'https://bank.example/path',
      frameId: 0,
      tab: {},
    }),
    null,
  );
});

// Engines below the supported minimum omit sender.origin; that is a refusal,
// never a reason to read the host out of sender.url.
test('refuses a sender that reports no origin', () => {
  assert.equal(
    getWebAuthnSenderOrigin({
      url: 'https://login.example.com/path',
      frameId: 0,
      tab: {},
    }),
    null,
  );
});

// Allow HTTP only for exact localhost, excluding subdomains and IP addresses.
test('accepts plain http only for localhost', () => {
  assert.equal(
    getWebAuthnSenderOrigin({ origin: 'http://localhost:8080', frameId: 0, tab: {} }),
    'http://localhost:8080',
  );
  assert.equal(
    getWebAuthnSenderOrigin({ origin: 'http://localhost', frameId: 0, tab: {} }),
    'http://localhost',
  );

  for (const origin of [
    'http://site.example',
    'http://intranet.example:9000',
    'http://localhost.example',
    'http://sub.localhost',
    'http://127.0.0.1:8080',
    'http://[::1]:8080',
  ]) {
    assert.equal(
      getWebAuthnSenderOrigin({ origin, frameId: 0, tab: {} }),
      null,
      `expected ${origin} to be refused`,
    );
  }
});

// localhost works as the default or explicit RP ID without a registrable parent.
test('resolves the RP ID for a localhost caller', () => {
  assert.equal(canonicalRpIdForOrigin(undefined, 'http://localhost:8080'), 'localhost');
  assert.equal(canonicalRpIdForOrigin('localhost', 'http://localhost:8080'), 'localhost');
  assert.equal(canonicalRpIdForOrigin('example.com', 'http://localhost:8080'), null);
});

test('keeps the port and rejects non-web schemes', () => {
  assert.equal(
    getWebAuthnSenderOrigin({
      origin: 'https://login.example.com:8443',
      frameId: 0,
      tab: {},
    }),
    'https://login.example.com:8443',
  );
  assert.equal(
    getWebAuthnSenderOrigin({
      origin: 'moz-extension://extension-id',
      frameId: 0,
      tab: {},
    }),
    null,
  );
});
