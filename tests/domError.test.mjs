// Unit checks for the helpers that carry a DOMException's identity across the
// extension layers. The path through the real modules is an integration test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isWebAuthnDomException,
  serializeError,
  sanitizeDomErrorName,
  toDomException,
} from '../.test-build/utils/domError.js';

test('serializeError keeps the name of a DOMException', () => {
  assert.deepEqual(
    serializeError(new DOMException('A passkey for this account already exists.', 'InvalidStateError')),
    { message: 'A passkey for this account already exists.', name: 'InvalidStateError' },
  );
});

test('serializeError leaves plain errors without a name', () => {
  // rootKeyMissing is matched by message in the dispatcher, so it must stay a
  // plain Error rather than become a DOMException.
  assert.deepEqual(serializeError(new Error('rootKeyMissing')), { message: 'rootKeyMissing' });
  assert.deepEqual(serializeError('boom'), { message: 'boom' });
});

test('toDomException rebuilds whitelisted names and collapses the rest to NotAllowedError', () => {
  for (const name of ['InvalidStateError', 'EncodingError', 'SecurityError']) {
    const error = toDomException('message', name);
    assert.ok(error instanceof DOMException);
    assert.equal(error.name, name);
    assert.equal(error.message, 'message');
  }
  assert.equal(toDomException('boom', 'HierarchyRequestError').name, 'NotAllowedError');
  assert.equal(toDomException('boom', undefined).name, 'NotAllowedError');
  assert.equal(toDomException(undefined, 'InvalidStateError').message, 'Operation failed');
});

test('isWebAuthnDomException: accepts supported DOMExceptions and rejects other errors', () => {
  assert.equal(
    isWebAuthnDomException(new DOMException('already registered', 'InvalidStateError')),
    true,
  );
  assert.equal(isWebAuthnDomException(new Error('temporary popup failure')), false);
  assert.equal(
    isWebAuthnDomException(new DOMException('unrelated DOM failure', 'HierarchyRequestError')),
    false,
  );
});

test('sanitizeDomErrorName: keeps supported names and maps others to NotAllowedError', () => {
  assert.equal(sanitizeDomErrorName('InvalidStateError'), 'InvalidStateError');
  assert.equal(sanitizeDomErrorName('EvilError'), 'NotAllowedError');
  assert.equal(sanitizeDomErrorName(undefined), 'NotAllowedError');
});
