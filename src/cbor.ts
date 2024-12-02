/**
 * Utility class for encoding and decoding CBOR data, specifically tailored for WebAuthn operations.
 */
export class WebAuthnCBOR {
  /**
   * Encodes a JavaScript value into CBOR format.
   * @param value - The value to encode.
   * @returns A Uint8Array containing the CBOR-encoded data.
   */
  static encode(value: any): Uint8Array {
    const encoder = new CBORWriter();
    encoder.write(value);
    return encoder.getResult();
  }

  /**
   * Decodes CBOR data into a JavaScript value.
   * @param data - The CBOR data to decode.
   * @returns The decoded JavaScript value.
   */
  static decode(data: ArrayBuffer | Uint8Array): any {
    const decoder = new CBORReader(data);
    return decoder.read();
  }

  /**
   * Creates a CBOR-encoded COSE key for EC2 (Elliptic Curve) keys.
   * @param x - The x-coordinate of the public key.
   * @param y - The y-coordinate of the public key.
   * @param alg - The algorithm identifier.
   * @returns A Uint8Array containing the CBOR-encoded COSE key.
   */
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

  /**
   * Creates a CBOR-encoded COSE key for RSA keys.
   * @param n - The modulus of the public key.
   * @param e - The exponent of the public key.
   * @param alg - The algorithm identifier.
   * @returns A Uint8Array containing the CBOR-encoded COSE key.
   */
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
}

/* ================================================
   CBOR Writer Class
=============================================== */

/**
 * Class for encoding data into CBOR format.
 */
class CBORWriter {
  private static readonly textEncoder = new TextEncoder();
  private data: Uint8Array;
  private size: number = 0;
  private capacity: number;

  constructor(initialCapacity: number = 256) {
    this.capacity = initialCapacity;
    this.data = new Uint8Array(initialCapacity);
  }

  /**
   * Gets the result of the encoding operation.
   * @returns A Uint8Array containing the CBOR-encoded data.
   */
  getResult(): Uint8Array {
    return this.data.subarray(0, this.size);
  }

  /**
   * Writes a value into the CBOR encoder.
   * @param value - The value to encode.
   */
  write(value: any): void {
    if (value === false) {
      this.writeByte(0xf4); // False
    } else if (value === true) {
      this.writeByte(0xf5); // True
    } else if (value === null) {
      this.writeByte(0xf6); // Null
    } else if (typeof value === 'number') {
      if (Number.isInteger(value)) {
        this.encodeInteger(value);
      } else {
        throw new Error(`Unsupported number type (float): ${value}`);
      }
    } else if (typeof value === 'string') {
      this.encodeString(value);
    } else if (value instanceof Uint8Array) {
      this.encodeByteString(value);
    } else if (Array.isArray(value)) {
      this.encodeArray(value);
    } else if (value instanceof Map) {
      this.encodeMapFromMap(value);
    } else if (typeof value === 'object' && value !== null) {
      this.encodeMapFromObject(value);
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

  private encodeArray(value: any[]): void {
    this.encodeMajorType(4, value.length);
    for (const item of value) {
      this.write(item);
    }
  }

  private encodeMapFromMap(map: Map<any, any>): void {
    this.encodeMajorType(5, map.size);
    for (const [key, value] of map) {
      this.write(key);
      this.write(value);
    }
  }

  private encodeMapFromObject(value: { [key: string]: any }): void {
    const keys = Object.keys(value);
    this.encodeMajorType(5, keys.length);
    for (const key of keys) {
      const keyNum = parseInt(key, 10);
      if (isNaN(keyNum)) {
        this.write(key);
      } else {
        this.write(keyNum);
      }
      this.write(value[key]);
    }
  }

  /**
   * Encodes a positive integer using the appropriate major type.
   * @param type - The major type (0 for positive integers, 1 for negative integers).
   * @param value - The integer value to encode.
   */
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

/* ================================================
   CBOR Reader Class
=============================================== */

/**
 * Class for decoding CBOR data into JavaScript values.
 */
class CBORReader {
  private static readonly textDecoder = new TextDecoder();
  private data: Uint8Array;
  private offset = 0;
  private length: number;

  constructor(input: ArrayBuffer | Uint8Array) {
    this.data = input instanceof ArrayBuffer ? new Uint8Array(input) : input;
    this.length = this.data.length;
  }

  /**
   * Reads and decodes the next value from the CBOR data.
   * @returns The decoded JavaScript value.
   */
  read(): any {
    if (this.offset >= this.length) {
      throw new Error('No more data to read');
    }

    const initialByte = this.data[this.offset++];
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    switch (majorType) {
      case 0:
        return this.decodePositiveInteger(additionalInfo);
      case 1:
        return this.decodeNegativeInteger(additionalInfo);
      case 2:
        return this.decodeByteString(additionalInfo);
      case 3:
        return this.decodeUtf8String(additionalInfo);
      case 4:
        return this.decodeArray(additionalInfo);
      case 5:
        return this.decodeMap(additionalInfo);
      case 7:
        return this.decodeSimpleValue(additionalInfo);
      default:
        throw new Error(`Unsupported major type: ${majorType}`);
    }
  }

  /* --------------------------------------------
     Decoding Methods
  -------------------------------------------- */

  private decodePositiveInteger(additionalInfo: number): number {
    return this.decodeLength(additionalInfo);
  }

  private decodeNegativeInteger(additionalInfo: number): number {
    return -1 - this.decodeLength(additionalInfo);
  }

  private decodeByteString(additionalInfo: number): Uint8Array {
    const length = this.decodeLength(additionalInfo);
    return this.readBytes(length);
  }

  private decodeUtf8String(additionalInfo: number): string {
    const bytes = this.decodeByteString(additionalInfo);
    return CBORReader.textDecoder.decode(bytes);
  }

  private decodeArray(additionalInfo: number): any[] {
    const length = this.decodeLength(additionalInfo);
    const arr = new Array(length);
    for (let i = 0; i < length; i++) {
      arr[i] = this.read();
    }
    return arr;
  }

  private decodeMap(additionalInfo: number): { [key: string]: any } {
    const length = this.decodeLength(additionalInfo);
    const obj: { [key: string]: any } = {};
    for (let i = 0; i < length; i++) {
      const key = this.read();
      obj[key] = this.read();
    }
    return obj;
  }

  private decodeSimpleValue(additionalInfo: number): any {
    switch (additionalInfo) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
        return null;
      default:
        throw new Error(`Unsupported simple value: ${additionalInfo}`);
    }
  }

  /* --------------------------------------------
     Reading Methods
  -------------------------------------------- */

  private decodeLength(additionalInfo: number): number {
    if (additionalInfo < 24) {
      return additionalInfo;
    } else if (additionalInfo === 24) {
      return this.readUint8();
    } else if (additionalInfo === 25) {
      return this.readUint16();
    } else if (additionalInfo === 26) {
      return this.readUint32();
    } else {
      throw new Error(`Unsupported length encoding: additionalInfo = ${additionalInfo}`);
    }
  }

  private readUint8(): number {
    if (this.offset + 1 > this.length) {
      throw new Error('Unexpected end of data while reading uint8');
    }
    return this.data[this.offset++];
  }

  private readUint16(): number {
    if (this.offset + 2 > this.length) {
      throw new Error('Unexpected end of data while reading uint16');
    }
    const value = (this.data[this.offset] << 8) | this.data[this.offset + 1];
    this.offset += 2;
    return value;
  }

  private readUint32(): number {
    if (this.offset + 4 > this.length) {
      throw new Error('Unexpected end of data while reading uint32');
    }
    const value =
      (this.data[this.offset] * 0x1000000) +
      ((this.data[this.offset + 1] << 16) |
        (this.data[this.offset + 2] << 8) |
        this.data[this.offset + 3]);
    this.offset += 4;
    return value;
  }

  private readBytes(length: number): Uint8Array {
    if (this.offset + length > this.length) {
      throw new Error('Unexpected end of data while reading bytes');
    }
    const value = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
}
