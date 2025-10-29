// NOTE: This CBOR implementation is tailored for WebAuthn.
// It implements only the subset needed for authenticator operations and COSE keys (EC2, RSA, OKP).

// Encode and decode CBOR data for WebAuthn operations.
export class WebAuthnCBOR {
  // Convert JavaScript value to CBOR format and return as Uint8Array.
  static encode(value: any): Uint8Array {
    const encoder = new CBORWriter();
    encoder.write(value);
    return encoder.getResult();
  }

  // Create CBOR-encoded COSE key for EC2 (Elliptic Curve) using x, y coordinates and algorithm identifier.
  static createEC2COSEKey(
    x: Uint8Array,
    y: Uint8Array,
    alg: number
  ): Uint8Array {
    const coseKey = new Map<number, any>([
      [1, 2],    // kty: Key Type (EC2)
      [3, alg],  // alg: Algorithm identifier
      [-1, 1],   // crv: Curve identifier (P-256)
      [-2, x],   // x-coordinate
      [-3, y],   // y-coordinate
    ]);
    return WebAuthnCBOR.encode(coseKey);
  }

  // Create CBOR-encoded COSE key for RSA using modulus (n), exponent (e), and algorithm identifier.
  static createRSACOSEKey(
    n: Uint8Array,
    e: Uint8Array,
    alg: number
  ): Uint8Array {
    const coseKey = new Map<number, any>([
      [1, 3],    // kty: Key Type (RSA)
      [3, alg],  // alg: Algorithm identifier
      [-1, n],   // n: Modulus
      [-2, e],   // e: Exponent
    ]);
    return WebAuthnCBOR.encode(coseKey);
  }

  // Create CBOR-encoded COSE key for OKP (Octet Key Pair, e.g., Ed25519) using public key bytes and algorithm identifier.
  static createOKPCOSEKey(
    x: Uint8Array,
    alg: number
  ): Uint8Array {
    // According to COSE and IANA references, an Ed25519 key can be represented with:
    // kty (1) = 1 (OKP),
    // 3 = alg (often -8 for Ed25519),
    // -1 = crv (6 for Ed25519),
    // -2 = x (the raw public key bytes).
    const coseKey = new Map<number, any>([
      [1, 1],    // kty: OKP
      [3, alg],  // alg: -8 for Ed25519
      [-1, 6],   // crv = 6 (Ed25519)
      [-2, x],   // x-coordinate (public key)
    ]);
    return WebAuthnCBOR.encode(coseKey);
  }
}

/* ================================================
   CBOR Writer Class
=============================================== */

// Handle encoding data into CBOR format.
class CBORWriter {
  private static readonly textEncoder = new TextEncoder();
  private data: Uint8Array;
  private size: number = 0;
  private capacity: number;

  constructor(initialCapacity: number = 256) {
    this.capacity = initialCapacity;
    this.data = new Uint8Array(initialCapacity);
  }

  // Return the final CBOR-encoded data as Uint8Array.
  getResult(): Uint8Array {
    return this.data.subarray(0, this.size);
  }

  // Encode a single value to CBOR bytes (helper for deterministic key sorting).
  private static encodeOne(value: any): Uint8Array {
    const writer = new CBORWriter(32);
    writer.write(value);
    return writer.getResult();
  }

  // Compare two keys by the bytewise lexicographic order of their CBOR encodings.
  // Per the CTAP2 spec: "These rules are equivalent to a lexicographical
  // comparison of the canonical encoding of keys for major types 0-3 and 7
  // (integers, strings, and simple values)." We only use integer and string
  // keys in WebAuthn structures (COSE_Key, attestationObject, attStmt), so
  // this ordering matches CTAP2 canonical CBOR for our purposes.
  private static compareCborKeys(a: any, b: any): number {
    const A = CBORWriter.encodeOne(a);
    const B = CBORWriter.encodeOne(b);

    // Bytewise lexicographic comparison:
    const n = Math.min(A.length, B.length);
    for (let i = 0; i < n; i++) {
      const diff = A[i] - B[i];
      if (diff !== 0) return diff;
    }
    // If one is a prefix of the other, the shorter sorts first.
    return A.length - B.length;
  }

  // Encode a value into the CBOR writer based on its type.
  write(value: any): void {
    if (typeof value === 'number') {
      if (Number.isInteger(value)) {
        this.encodeInteger(value);
      } else {
        throw new Error(`Unsupported number type (float): ${value}`);
      }
    } else if (typeof value === 'string') {
      this.encodeString(value);
    } else if (value instanceof Uint8Array) {
      this.encodeByteString(value);
    } else if (value instanceof Map) {
      this.encodeMap(value);
    } else {
      throw new Error(`Unsupported type during CBOR encoding: ${typeof value}`);
    }
  }

  /* --------------------------------------------
     Encoding Methods
  -------------------------------------------- */

  private encodeInteger(value: number): void {
    if (value >= 0) {
      this.encodeMajorType(0, value);
    } else {
      this.encodeMajorType(1, -1 - value);
    }
  }

  private encodeByteString(value: Uint8Array): void {
    this.encodeMajorType(2, value.length);
    this.writeBytes(value);
  }

  private encodeString(value: string): void {
    const utf8data = CBORWriter.textEncoder.encode(value);
    this.encodeMajorType(3, utf8data.length);
    this.writeBytes(utf8data);
  }

  // Encode a Map as a CBOR map with deterministic key order compatible with
  // CTAP2 expectations for WebAuthn structures.
  private encodeMap(map: Map<any, any>): void {
    // Collect entries and sort them by the bytewise lexicographic order of their
    // CBOR-encoded keys. For the string and integer keys used in WebAuthn
    // structures (attestationObject, attStmt, COSE_Key), this matches CTAP2’s
    // canonical CBOR requirements.
    const entries = Array.from(map.entries());
    entries.sort((a, b) => CBORWriter.compareCborKeys(a[0], b[0]));

    // Major type 5 = map
    this.encodeMajorType(5, entries.length);
    for (const [key, value] of entries) {
      this.write(key);
      this.write(value);
    }
  }

  private encodeMajorType(type: number, value: number): void {
    if (value < 24) {
      this.writeByte((type << 5) | value);
    } else if (value < 256) {
      this.writeByte((type << 5) | 24);
      this.writeByte(value);
    } else if (value < 65536) {
      this.writeByte((type << 5) | 25);
      this.writeUint16(value);
    } else if (value < 4294967296) {
      this.writeByte((type << 5) | 26);
      this.writeUint32(value);
    } else {
      throw new Error(`Integer value too large to encode: ${value}`);
    }
  }

  /* --------------------------------------------
     Writing Methods
  -------------------------------------------- */

  private writeByte(byte: number): void {
    this.ensureCapacity(1);
    this.data[this.size++] = byte;
  }

  private writeBytes(bytes: Uint8Array): void {
    this.ensureCapacity(bytes.length);
    this.data.set(bytes, this.size);
    this.size += bytes.length;
  }

  private writeUint16(value: number): void {
    this.ensureCapacity(2);
    this.data[this.size++] = (value >> 8) & 0xff;
    this.data[this.size++] = value & 0xff;
  }

  private writeUint32(value: number): void {
    this.ensureCapacity(4);
    this.data[this.size++] = (value >> 24) & 0xff;
    this.data[this.size++] = (value >> 16) & 0xff;
    this.data[this.size++] = (value >> 8) & 0xff;
    this.data[this.size++] = value & 0xff;
  }

  /* --------------------------------------------
     Buffer Management
  -------------------------------------------- */

  private ensureCapacity(needed: number): void {
    const requiredSize = this.size + needed;
    if (requiredSize > this.capacity) {
      this.growBuffer(requiredSize);
    }
  }

  private growBuffer(minCapacity: number): void {
    const newCapacity = Math.max(this.capacity * 2, minCapacity);
    const newData = new Uint8Array(newCapacity);
    newData.set(this.data.subarray(0, this.size));
    this.data = newData;
    this.capacity = newCapacity;
  }
}
