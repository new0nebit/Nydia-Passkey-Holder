import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createVerify, webcrypto } from 'node:crypto';
import { test } from 'node:test';

import { rawToDer } from '../.test-build/utils/der.js';

function raw(rFirst, sFirst) {
  const bytes = new Uint8Array(64).fill(0x11);
  bytes.set(rFirst, 0);
  bytes.set(sFirst, 32);
  return bytes.buffer;
}

function der(buffer) {
  return Buffer.from(new Uint8Array(buffer)).toString('hex');
}

test('drops redundant leading zero bytes', () => {
  // r becomes 30 bytes starting 7f, s 31 bytes starting 01.
  const bytes = new Uint8Array(rawToDer(raw([0x00, 0x00, 0x7f], [0x00, 0x01])));
  assert.equal(bytes[0], 0x30);
  assert.equal(bytes[2], 0x02);
  assert.equal(bytes[3], 30);
  assert.equal(bytes[4], 0x7f);
  assert.equal(bytes[4 + 30], 0x02);
  assert.equal(bytes[4 + 30 + 1], 31);
  assert.equal(bytes[4 + 30 + 2], 0x01);
  assert.equal(bytes[1], bytes.length - 2);
});

test('keeps one zero byte when the high bit is set', () => {
  // r: 32 bytes with the high bit set gain a 0x00. s: the redundant 0x00 is
  // dropped first, then the remaining 31 bytes gain the required one.
  const bytes = new Uint8Array(rawToDer(raw([0x80], [0x00, 0x80])));
  assert.equal(bytes[3], 33);
  assert.equal(bytes[4], 0x00);
  assert.equal(bytes[5], 0x80);
  assert.equal(bytes[4 + 33 + 1], 32);
  assert.equal(bytes[4 + 33 + 2], 0x00);
  assert.equal(bytes[4 + 33 + 3], 0x80);
});

test('encodes a zero-valued integer as a single byte', () => {
  const zero = new Uint8Array(64);
  zero[63] = 0x01;
  assert.equal(der(rawToDer(zero.buffer)), '3006020100020101');
});

test('rejects a raw signature of the wrong length', () => {
  assert.throws(() => rawToDer(new ArrayBuffer(63)), /Invalid raw signature length/);
});

// The original bug needs r or s to start with 0x00 followed by a byte below
// 0x80: that zero is redundant, unlike the sign byte before 0x80..0xff. Each
// component lands there about once in 512 signatures. Keep signing until both
// have occurred and require OpenSSL to accept every conversion.
test('OpenSSL verifies converted WebCrypto signatures, including leading-zero r and s', async () => {
  const { subtle } = webcrypto;
  const keys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const spki = Buffer.from(await subtle.exportKey('spki', keys.publicKey));

  let leadingZeroR = 0;
  let leadingZeroS = 0;
  for (let i = 0; i < 20000 && (leadingZeroR === 0 || leadingZeroS === 0); i++) {
    const message = webcrypto.getRandomValues(new Uint8Array(32));
    const signature = new Uint8Array(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, message),
    );
    if (signature[0] === 0 && signature[1] < 0x80) leadingZeroR++;
    if (signature[32] === 0 && signature[33] < 0x80) leadingZeroS++;

    const verifier = createVerify('SHA256');
    verifier.update(message);
    assert.ok(
      verifier.verify({ key: spki, format: 'der', type: 'spki' }, Buffer.from(rawToDer(signature.buffer))),
      `signature ${i} was rejected`,
    );
  }

  assert.ok(leadingZeroR > 0 && leadingZeroS > 0, 'no redundant leading zero in r and s was produced');
});
