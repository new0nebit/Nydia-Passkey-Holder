// WebAuthn requires ES256 signatures in ASN.1 DER, while WebCrypto returns the
// raw r || s form. DER encodes each INTEGER in its minimal form: redundant
// leading zero bytes must be dropped, and a single 0x00 is required when the
// high bit is set so the value stays positive. Strict verifiers (OpenSSL, Go)
// reject anything else, so a non-minimal encoding fails roughly one ES256
// assertion in a few hundred.

function derInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const minimal = bytes.subarray(start);

  if (minimal[0] & 0x80) {
    const padded = new Uint8Array(minimal.length + 1);
    padded.set(minimal, 1);
    return padded;
  }
  return minimal;
}

// Convert a raw 64-byte P-256 ECDSA signature to DER.
export function rawToDer(rawSignature: ArrayBuffer): ArrayBuffer {
  const raw = new Uint8Array(rawSignature);
  if (raw.length !== 64) {
    throw new Error('Invalid raw signature length');
  }

  const r = derInteger(raw.subarray(0, 32));
  const s = derInteger(raw.subarray(32, 64));

  // At most 2 + (2 + 33) + (2 + 33) = 72 bytes, so every length fits in one byte.
  const der = new Uint8Array(6 + r.length + s.length);
  der.set([0x30, 4 + r.length + s.length, 0x02, r.length], 0);
  der.set(r, 4);
  der.set([0x02, s.length], 4 + r.length);
  der.set(s, 6 + r.length);

  return der.buffer;
}
