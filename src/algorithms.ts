// Web Crypto API
const crypto = self.crypto;
const subtle = crypto.subtle;

/**
 * Interface for signing algorithms used in WebAuthn operations.
 */
export interface SigningAlgorithm {
  generateKeyPair(): Promise<CryptoKeyPair>;
  sign(data: ArrayBuffer, key: CryptoKey): Promise<ArrayBuffer>;
}

/**
 * Implementation of the ES256 signing algorithm (ECDSA with SHA-256).
 */
export class ES256 implements SigningAlgorithm {
  /**
   * Generates an ECDSA key pair using the P-256 curve.
   */
  async generateKeyPair(): Promise<CryptoKeyPair> {
    return await subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair;
  }

  /**
   * Signs data using the private key with ECDSA and SHA-256.
   * @param data - The data to sign.
   * @param key - The private key for signing.
   */
  async sign(data: ArrayBuffer, key: CryptoKey): Promise<ArrayBuffer> {
    return await subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      key,
      data
    );
  }
}

/**
 * Implementation of the RS256 signing algorithm (RSASSA-PKCS1-v1_5 with SHA-256).
 */
export class RS256 implements SigningAlgorithm {
  /**
   * Generates an RSA key pair with a modulus length of 2048 bits.
   */
  async generateKeyPair(): Promise<CryptoKeyPair> {
    return await subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Exponent 65537
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair;
  }

  /**
   * Signs data using the private key with RSASSA-PKCS1-v1_5 and SHA-256.
   * @param data - The data to sign.
   * @param key - The private key for signing.
   */
  async sign(data: ArrayBuffer, key: CryptoKey): Promise<ArrayBuffer> {
    return await subtle.sign(
      {
        name: 'RSASSA-PKCS1-v1_5',
      },
      key,
      data
    );
  }
}
