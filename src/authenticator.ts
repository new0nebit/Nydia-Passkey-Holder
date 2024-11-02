import * as cbor from 'cbor';
import base64url from 'base64url';

// Use the browser's crypto API
const crypto = window.crypto;
const subtle = crypto.subtle;

import {
  readStoredCredentials,
  generateUserIdHash,
  createUniqueId,
  savePrivateKey,
  loadPrivateKey,
  findCredential,
  updateCredentialCounter,
  getMemoryStore
} from './store';

const AAGUID: Buffer = Buffer.from([
  0x4E, 0x79, 0x64, 0x69,
  0x61, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
]);

interface Authenticator {
  aaguid: Buffer;
  createAuthenticatorData(
    rpId: string,
    credentialId: Buffer,
    publicKey: PublicKey,
    algorithm: SigningAlgorithm
  ): Promise<Buffer>;
}

interface CollectedClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin: boolean;
  topOrigin?: string;
}

interface PublicKeyCredentialCreationOptions {
  rp: RelyingParty;
  user: User;
  challenge: Challenge;
  pubKeyCredParams: PubKeyCredParam[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: string;
  extensions?: Extensions;
  origin: string;
  rpId?: string;
}

interface RelyingParty {
  name: string;
  id: string;
}

interface User {
  id: UserId;
  name: string;
  displayName: string;
}

type UserId = string | ArrayBuffer | Uint8Array;

type Challenge = string | ArrayBuffer | Uint8Array;

interface PubKeyCredParam {
  type: string;
  alg: number;
}

interface PublicKeyCredentialDescriptor {
  type: string;
  id: string;
  transports?: string[];
}

interface AuthenticatorSelectionCriteria {
  residentKey?: string;
  requireResidentKey?: boolean;
  userVerification?: string;
}

interface Extensions {
  credProps?: boolean;
}

interface Credential {
  type: string;
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    publicKeyAlgorithm?: number;
    publicKey?: string;
  };
}

interface AuthenticatorAttestationResponse {
  clientDataJSON: Buffer;
  attestationObject: Buffer;
}

interface PublicKeyCredentialRequestOptions {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptor[];
    userVerification?: string;
    extensions?: Extensions;
  };
  origin: string;
  rpId?: string;
}

interface AuthenticatorAssertionResponse {
  type: string;
  id: string;
  rawId: string;
  response: AssertionResponseData;
}

interface AssertionResponseData {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string | null;
}

export enum SecretKeyType {
  Ecdsa,
  Rsa
}

export type SecretKey = {
  type: SecretKeyType.Ecdsa | SecretKeyType.Rsa;
  key: CryptoKey;
};

export type PublicKey = {
  type: SecretKeyType.Ecdsa | SecretKeyType.Rsa;
  key: CryptoKey;
};

export interface SigningAlgorithm {
  generateKeyPair(): Promise<[SecretKey, PublicKey]>;
  sign(secretKey: SecretKey, data: Buffer): Promise<Buffer>;
  createCoseKey(publicKey: PublicKey): Promise<Buffer>;
}

function logInfo(message: string, data?: any) {
  if (data !== undefined) {
    console.log(`[Authenticator] ${message}:`, data);
  } else {
    console.log(`[Authenticator] ${message}`);
  }
}

function logError(message: string, error?: any) {
  console.error(`[Authenticator Error] ${message}`, error);
}

function logAuth(message: string, data?: any) {
  if (data !== undefined) {
    console.log(`[Authenticator] ${message}:`, data);
  } else {
    console.log(`[Authenticator] ${message}`);
  }
}

// Implementation of ES256 algorithm
export class ES256 implements SigningAlgorithm {
  async generateKeyPair(): Promise<[SecretKey, PublicKey]> {
    logInfo(`Generating ES256 key pair`);
    const keyPair = await subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
    logInfo('ES256 key pair generated successfully');
    return [
      { type: SecretKeyType.Ecdsa, key: keyPair.privateKey },
      { type: SecretKeyType.Ecdsa, key: keyPair.publicKey }
    ];
  }

  async sign(secretKey: SecretKey, data: Buffer): Promise<Buffer> {
    if (secretKey.type !== SecretKeyType.Ecdsa) {
      throw new Error('Invalid key type for ES256');
    }
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      secretKey.key,
      data
    );
    return Buffer.from(signature);
  }

  async createCoseKey(publicKey: PublicKey): Promise<Buffer> {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey.key);
    const coseKey = new Map();
    coseKey.set(1, 2); // kty: EC2
    coseKey.set(3, -7); // alg: ES256
    coseKey.set(-1, 1); // crv: P-256
    coseKey.set(-2, Buffer.from(base64UrlDecode(jwk.x!))); // x coordinate
    coseKey.set(-3, Buffer.from(base64UrlDecode(jwk.y!))); // y coordinate
    return cbor.encode(coseKey);
  }
}

// Implementation of RS256 algorithm
export class RS256 implements SigningAlgorithm {
  async generateKeyPair(): Promise<[SecretKey, PublicKey]> {
    logInfo(`Generating RS256 key pair`);
    const keyPair = await subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );
    return [
      { type: SecretKeyType.Rsa, key: keyPair.privateKey },
      { type: SecretKeyType.Rsa, key: keyPair.publicKey }
    ];
  }

  async sign(secretKey: SecretKey, data: Buffer): Promise<Buffer> {
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      secretKey.key,
      data
    );
    return Buffer.from(signature);
  }

  async createCoseKey(publicKey: PublicKey): Promise<Buffer> {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey.key);
    const coseKey = new Map();
    coseKey.set(1, 3); // kty: RSA
    coseKey.set(3, -257); // alg: RS256
    coseKey.set(-1, Buffer.from(base64UrlDecode(jwk.n!))); // modulus
    coseKey.set(-2, Buffer.from(base64UrlDecode(jwk.e!))); // exponent
    return cbor.encode(coseKey);
  }
}

// Helper functions
export function base64UrlEncode(buffer: Buffer | ArrayBuffer): string {
  return base64url.encode(Buffer.from(buffer));
}

export function base64UrlDecode(str: string): Buffer {
  return base64url.toBuffer(str);
}

async function sha256(data: Buffer | Uint8Array): Promise<Buffer> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Buffer.from(hashBuffer);
}

async function getPublicKeyDer(publicKey: CryptoKey, algorithm: SigningAlgorithm): Promise<Buffer> {
  if (algorithm instanceof ES256 || algorithm instanceof RS256) {
    const exportedKey = await crypto.subtle.exportKey('spki', publicKey);
    return Buffer.from(exportedKey);
  }
  throw new Error('Unsupported algorithm');
}

async function createAttestationObject(authData: Buffer): Promise<Buffer> {
  const fmt = 'none';
  const attStmt = {};

  const attestationObject = {
    fmt,
    authData,
    attStmt
  };

  return cbor.encode(attestationObject);
}

function chooseAlgorithm(params: PubKeyCredParam[]): SigningAlgorithm {
  for (const param of params) {
    if (param.alg === -7) {
      return new ES256();
    }
    if (param.alg === -257) {
      return new RS256();
    }
  }
  throw new Error('No supported algorithm found');
}

function generateRandomBytes(size: number): Uint8Array {
  const array = new Uint8Array(size);
  window.crypto.getRandomValues(array);
  return array;
}

function createClientDataJSON(
  type: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string
): Buffer {
  const clientData: CollectedClientData = {
    type,
    challenge,
    origin,
    crossOrigin: false
  };
  return Buffer.from(JSON.stringify(clientData));
}

// Convert raw ECDSA signature to DER format
function rawToDer(rawSignature: ArrayBuffer): ArrayBuffer {
  const raw = new Uint8Array(rawSignature);
  if (raw.length !== 64) {
    throw new Error('Invalid raw signature length');
  }

  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  const prependZeroIfNeeded = (buffer: Uint8Array): Uint8Array => {
    if (buffer[0] & 0x80) {
      const extendedBuffer = new Uint8Array(buffer.length + 1);
      extendedBuffer[0] = 0x00;
      extendedBuffer.set(buffer, 1);
      return extendedBuffer;
    }
    return buffer;
  };

  const rDer = prependZeroIfNeeded(r);
  const sDer = prependZeroIfNeeded(s);

  const rLen = rDer.length;
  const sLen = sDer.length;

  const totalLen = rLen + sLen + 4; // 2 bytes for each INTEGER header
  const derSignature = new Uint8Array(totalLen + 2); // 2 bytes for SEQUENCE header

  derSignature[0] = 0x30; // SEQUENCE tag
  derSignature[1] = totalLen;
  derSignature[2] = 0x02; // INTEGER tag for r
  derSignature[3] = rLen;
  derSignature.set(rDer, 4);
  derSignature[4 + rLen] = 0x02; // INTEGER tag for s
  derSignature[5 + rLen] = sLen;
  derSignature.set(sDer, 6 + rLen);

  return derSignature.buffer;
}

// Main functions
export async function createCredential(options: PublicKeyCredentialCreationOptions): Promise<Credential | null> {
  logAuth('Starting credential creation...');
  logAuth(`Options:`, JSON.stringify(options));

  try {
    // Process options.user.id
    let userId: ArrayBuffer;
    if (typeof options.user.id === 'string') {
      userId = base64UrlDecode(options.user.id).buffer;
      logAuth('userId decoded from string');
    } else if (options.user.id instanceof ArrayBuffer) {
      userId = options.user.id;
      logAuth('userId is ArrayBuffer');
    } else if (ArrayBuffer.isView(options.user.id)) {
      userId = options.user.id.buffer.slice(
        options.user.id.byteOffset,
        options.user.id.byteOffset + options.user.id.byteLength
      );
      logAuth('userId is ArrayBufferView');
    } else {
      logAuth(`Invalid user.id type: ${typeof options.user.id}`);
      throw new Error('Invalid user.id type');
    }

    const rpId = options.rpId || options.rp.id || new URL(options.origin).hostname;
    logAuth(`rpId:`, rpId);

    const algorithm = chooseAlgorithm(options.pubKeyCredParams);
    logAuth(`Chosen algorithm:`, algorithm instanceof ES256 ? 'ES256' : 'RS256');

    const userIdHash = await generateUserIdHash(rpId, userId);
    logAuth(`userIdHash generated:`, userIdHash);

    const storedCredentials = await readStoredCredentials();
    const existingCredential = Object.values(storedCredentials).find(
      cred => cred.userIdHash === userIdHash
    );

    if (existingCredential) {
      logAuth(`Existing credential found for user ${options.user.name} and RP ${rpId}`);
      return null;
    }

    logAuth(`Generating key pair for algorithm:`, algorithm instanceof ES256 ? 'ES256' : 'RS256');
    const [secretKey, publicKey] = await algorithm.generateKeyPair();
    logAuth('Key pair generated successfully');

    const credentialId = generateRandomBytes(32);
    const credentialIdEncoded = base64UrlEncode(credentialId);
    logAuth(`Credential ID generated:`, credentialIdEncoded);

    const publicKeyDer = await getPublicKeyDer(publicKey.key, algorithm);
    const publicKeyAlgorithm = algorithm instanceof ES256 ? -7 : -257;
    logAuth(`Public key DER generated, algorithm:`, publicKeyAlgorithm);

    await savePrivateKey(
      new Uint8Array(credentialId),
      rpId,
      secretKey,
      userId,
      publicKeyDer,
      publicKeyAlgorithm,
      userIdHash,
      options.user.name,
      options.user.displayName
    );

    logAuth('Private key saved');

    const uniqueId = await createUniqueId(rpId, credentialIdEncoded);
    logAuth(`UniqueId associated with credential created:`, uniqueId);

    const authenticator: Authenticator = {
      aaguid: AAGUID,
      createAuthenticatorData: async (
        rpId: string,
        credentialId: Buffer,
        publicKey: PublicKey,
        algorithm: SigningAlgorithm
      ): Promise<Buffer> => {
        const rpIdHash = await sha256(Buffer.from(rpId));
        const flags = Buffer.from([0x45]); // Flags: AT (0x40) | UP (0x01) = 0x41
        const signCount = Buffer.alloc(4); // Sign count set to zero
        const aaguid = AAGUID;
        const credIdLength = Buffer.alloc(2);
        credIdLength.writeUInt16BE(credentialId.length, 0);
        const publicKeyBuffer = await algorithm.createCoseKey(publicKey);
        return Buffer.concat([
          rpIdHash,
          flags,
          signCount,
          aaguid,
          credIdLength,
          credentialId,
          publicKeyBuffer
        ]);
      }
    };

    const authData = await authenticator.createAuthenticatorData(
      rpId,
      Buffer.from(credentialId),
      publicKey,
      algorithm
    );
    logAuth('Authenticator data created');

    const challengeBuffer = base64UrlDecode(options.challenge as string);
    const challengeBase64 = base64UrlEncode(challengeBuffer);

    const clientDataJSON = createClientDataJSON('webauthn.create', challengeBase64, options.origin);
    logAuth('Client data JSON created');

    const attestationObject = await createAttestationObject(authData);
    logAuth('Attestation object created');

    const createResponse: Credential = {
      type: 'public-key',
      id: credentialIdEncoded,
      rawId: credentialIdEncoded,
      response: {
        clientDataJSON: base64UrlEncode(clientDataJSON),
        attestationObject: base64UrlEncode(attestationObject),
        publicKeyAlgorithm,
        publicKey: Array.from(publicKeyDer).join(', ')
      }
    };

    logAuth('Credential created successfully');
    logAuth('Credential:', createResponse);

    logAuth('Attempting to save attestation response to MemoryStore');
    const memoryStore = getMemoryStore();
    logAuth('MemoryStore instance retrieved');
    memoryStore.saveAttestationResponse(createResponse);
    logAuth('Attestation response saved to MemoryStore');

    return createResponse;
  } catch (error) {
    logError(`Error in createCredential: ${error.message}`, error);
    throw error;
  }
}

export async function handleGetAssertion(
  options: PublicKeyCredentialRequestOptions
): Promise<AuthenticatorAssertionResponse> {
  logAuth('Starting assertion handling...');
  logAuth('Assertion options:', JSON.stringify(options, null, 2));

  // Ensure challenge is present
  if (!options.publicKey || !options.publicKey.challenge) {
    throw new Error('Challenge is missing in the options');
  }

  // Log the type and value of the challenge
  logAuth('Challenge type:', typeof options.publicKey.challenge);
  logAuth('Challenge value:', options.publicKey.challenge);

  // Decode the challenge
  let challengeBuffer: Uint8Array;
  let challengeString: string;

  if (typeof options.publicKey.challenge === 'string') {
    // The challenge is a base64url-encoded string
    challengeBuffer = base64UrlDecode(options.publicKey.challenge);
    challengeString = options.publicKey.challenge;
  } else {
    // The challenge is an ArrayBuffer
    challengeBuffer = new Uint8Array(options.publicKey.challenge);
    challengeString = base64UrlEncode(challengeBuffer);
  }

  logAuth('Challenge buffer (hex):', Buffer.from(challengeBuffer).toString('hex'));
  logAuth('Challenge string:', challengeString);

  // Find the stored credential
  const storedCredential = await findCredential(options);

  if (!storedCredential) {
    throw new Error('No matching credential found');
  }

  const rpId = options.publicKey.rpId || new URL(options.origin).hostname;
  logAuth('Using rpId:', rpId);

  // Load the private key and algorithm
  const [secretKey, algorithm, counter] = await loadPrivateKey(storedCredential.credentialId);

  logAuth('Loaded private key and algorithm:', {
    secretKeyType: secretKey.type,
    algorithmName: algorithm instanceof ES256 ? 'ES256' : 'RS256',
    counter
  });

  // Construct authenticatorData
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));
  logAuth('Computed rpIdHash (hex):', Buffer.from(rpIdHash).toString('hex'));

  const flags = new Uint8Array([0x01]); // UP=1
  const signCount = new Uint8Array(4);
  const dataView = new DataView(signCount.buffer);
  dataView.setUint32(0, counter + 1, false); // Big-endian

  const authenticatorData = new Uint8Array([
    ...rpIdHash,
    ...flags,
    ...signCount
  ]);

  logAuth('Constructed authenticatorData (hex):', Buffer.from(authenticatorData).toString('hex'));

  // Create clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: challengeString,
    origin: options.origin,
    crossOrigin: false,
  };

  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

  logAuth('Constructed clientDataJSON (string):', JSON.stringify(clientData));
  logAuth('clientDataJSON (hex):', Buffer.from(clientDataJSON).toString('hex'));

  // Compute clientDataHash
  const clientDataHash = await sha256(clientDataJSON);
  logAuth('Computed clientDataHash (hex):', Buffer.from(clientDataHash).toString('hex'));

  // Construct signatureBase
  const signatureBase = new Uint8Array([
    ...authenticatorData,
    ...clientDataHash
  ]);

  logAuth('Constructed signatureBase (hex):', Buffer.from(signatureBase).toString('hex'));

  // Generate the signature
  let signature: ArrayBuffer;

  if (algorithm instanceof ES256) {
    // Generate the raw signature
    const rawSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      secretKey.key,
      signatureBase
    );
    logAuth('Generated signature using ES256 (raw format)');

    // Convert raw signature to DER format
    signature = rawToDer(rawSignature);
    logAuth('Converted signature to DER format');

    // Log signature details
    const signatureBytes = new Uint8Array(signature);
    logAuth('Signature length after DER conversion:', signatureBytes.length);
    logAuth('Signature (DER hex):', Buffer.from(signature).toString('hex'));

    // Verify if the signature is DER-encoded
    const firstByte = signatureBytes[0];
    logAuth('First byte of ECDSA signature (hex):', firstByte.toString(16));

    if (firstByte === 0x30) {
      logAuth('Signature appears to be DER-encoded');
    } else {
      logAuth('Signature does not appear to be DER-encoded');
    }
  } else if (algorithm instanceof RS256) {
    signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      secretKey.key,
      signatureBase
    );
    logAuth('Generated signature using RS256');

    // Log signature details
    const signatureBytes = new Uint8Array(signature);
    logAuth('Signature length:', signatureBytes.length);
    logAuth('Signature (hex):', Buffer.from(signature).toString('hex'));
  } else {
    throw new Error('Unsupported algorithm');
  }

  logAuth('Signature (base64url):', base64UrlEncode(Buffer.from(signature)));

  // Update the credential counter
  await updateCredentialCounter(storedCredential.credentialId);

  // Construct the response
  const response: AuthenticatorAssertionResponse = {
    type: 'public-key',
    id: storedCredential.credentialId,
    rawId: storedCredential.credentialId,
    response: {
      clientDataJSON: base64UrlEncode(clientDataJSON),
      authenticatorData: base64UrlEncode(authenticatorData),
      signature: base64UrlEncode(Buffer.from(signature)),
      userHandle: storedCredential.userHandle ? storedCredential.userHandle : null
    }
  };

  logAuth('Constructed assertion response:', JSON.stringify(response, null, 2));

  return response;
}

// Initialization function
export function initializeAuthenticator() {
  try {
    logInfo('Initializing WebAuthn authenticator...');
    const storedCredentials = readStoredCredentials();
    logInfo(`Found ${Object.keys(storedCredentials).length} stored credentials`);
    logInfo('WebAuthn authenticator initialized successfully');
  } catch (error) {
    logError('Error during authenticator initialization', error);
    throw error;
  }
}
