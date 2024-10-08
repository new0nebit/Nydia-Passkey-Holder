import * as crypto from 'crypto';
import * as fs from 'fs';
import * as cbor from 'cbor';
import base64url from 'base64url';

import { 
  readStoredCredentials,  // Read all stored credentials
  generateUserIdHash,     // Generate user ID hash
  createUniqueId,         // Create unique passkey identifier
  savePrivateKey,         // Save private key
  loadPrivateKey,         // Load private key
  findCredential,         // Find a specific credential
  updateCredentialCounter // Update credential usage counter
} from './store';

const AAGUID: Buffer = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

interface Authenticator {
  aaguid: Buffer;
  createAuthenticatorData(rpId: string, credentialId: Buffer, publicKey: PublicKey, algorithm: SigningAlgorithm): Promise<Buffer>;
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

type UserId = string | { data: Buffer };

type Challenge = string | { data: Buffer };

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
  type: SecretKeyType.Ecdsa;
  key: crypto.KeyObject;
} | {
  type: SecretKeyType.Rsa;
  key: crypto.KeyObject;
};

export type PublicKey = {
  type: SecretKeyType.Ecdsa;
  key: crypto.KeyObject;
} | {
  type: SecretKeyType.Rsa;
  key: crypto.KeyObject;
};

export interface SigningAlgorithm {
  generateKeyPair(): Promise<[SecretKey, PublicKey]>;
  sign(secretKey: SecretKey, data: Buffer): Promise<Buffer>;
  createCoseKey(publicKey: PublicKey): Promise<Buffer>;
}

export class ES256 implements SigningAlgorithm {
  async generateKeyPair(): Promise<[SecretKey, PublicKey]> {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256'
    });
    return [
      { type: SecretKeyType.Ecdsa, key: privateKey },
      { type: SecretKeyType.Ecdsa, key: publicKey }
    ];
  }

  async sign(secretKey: SecretKey, data: Buffer): Promise<Buffer> {
    if (secretKey.type !== SecretKeyType.Ecdsa) {
      throw new Error('Invalid key type for ES256');
    }
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(secretKey.key);
  }

  async createCoseKey(publicKey: PublicKey): Promise<Buffer> {
    if (publicKey.type !== SecretKeyType.Ecdsa) {
      throw new Error('Invalid key type for ES256');
    }
    const jwk = publicKey.key.export({ format: 'jwk' }) as any;
    const coseKey = new Map();
    coseKey.set(1, 2); // kty: EC2
    coseKey.set(3, -7); // alg: ES256
    coseKey.set(-1, 1); // crv: P-256
    coseKey.set(-2, Buffer.from(jwk.x, 'base64')); // x coordinate
    coseKey.set(-3, Buffer.from(jwk.y, 'base64')); // y coordinate
    return cbor.encode(coseKey);
  }
}

export class RS256 implements SigningAlgorithm {
  async generateKeyPair(): Promise<[SecretKey, PublicKey]> {
    const { privateKey, publicKey } = await crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 65537
    });
    return [
      { type: SecretKeyType.Rsa, key: privateKey },
      { type: SecretKeyType.Rsa, key: publicKey }
    ];
  }

  async sign(secretKey: SecretKey, data: Buffer): Promise<Buffer> {
    if (secretKey.type !== SecretKeyType.Rsa) {
      throw new Error('Invalid key type for RS256');
    }
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(secretKey.key);
  }

  async createCoseKey(publicKey: PublicKey): Promise<Buffer> {
    if (publicKey.type !== SecretKeyType.Rsa) {
      throw new Error('Invalid key type for RS256');
    }
    const jwk = publicKey.key.export({ format: 'jwk' }) as any;
    const coseKey = new Map();
    coseKey.set(1, 3); // kty: RSA
    coseKey.set(3, -257); // alg: RS256
    coseKey.set(-1, Buffer.from(jwk.n, 'base64'));
    coseKey.set(-2, Buffer.from(jwk.e, 'base64'));
    return cbor.encode(coseKey);
  }
}

export function base64UrlEncode(buffer: Buffer): string {
  return base64url.encode(buffer);
}

export function base64UrlDecode(str: string): Buffer {
  return base64url.toBuffer(str);
}

function sha256(data: Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

function getPublicKeyDer(publicKey: crypto.KeyObject, algorithm: SigningAlgorithm): Buffer {
  if (algorithm instanceof ES256 || algorithm instanceof RS256) {
    return publicKey.export({ type: 'spki', format: 'der' });
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

async function savePublicKeyToFile(publicKey: crypto.KeyObject, algorithm: SigningAlgorithm, filename: string): Promise<void> {
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  fs.writeFileSync(filename, pem);
}

async function parseCreateOptions(input: string): Promise<PublicKeyCredentialCreationOptions> {
  const decoded = base64url.decode(input.trim());
  const json = JSON.parse(decoded);
  return {
    ...json.publicKey,
    origin: json.origin,
    rpId: json.rpId
  };
}

async function parseGetOptions(input: string): Promise<PublicKeyCredentialRequestOptions> {
  const decoded = base64url.decode(input.trim());
  const json = JSON.parse(decoded);
  return {
    publicKey: json.publicKey,
    origin: json.origin,
    rpId: json.rpId
  };
}

function isValidDomain(domain: string): boolean {
  return /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i.test(domain);
}

function isRegistrableDomainSuffix(suffix: string, domain: string): boolean {
  return domain.endsWith(suffix);
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

async function createCredential(options: PublicKeyCredentialCreationOptions, forceCreate: boolean = false): Promise<Credential | null> {
  const rpId = options.rpId || options.rp.id || new URL(options.origin).hostname;
  const algorithm = chooseAlgorithm(options.pubKeyCredParams);

  console.log('\nAttestation ceremony begins...\n');

  const userIdHash = generateUserIdHash(rpId, options.user.id);
  const storedCredentials = readStoredCredentials();
  const existingCredential = Object.values(storedCredentials).find(cred => cred.userIdHash === userIdHash);

  if (existingCredential && !forceCreate) {
    console.log(`Existing credential found for user \x1b[38;5;223m${options.user.name}\x1b[0m and RP \x1b[94m${rpId}\x1b[0m`);
    return null;
  }

  console.log(`    Chosen algorithm: \x1b[38;5;208m${algorithm instanceof ES256 ? 'ES256' : 'RS256'}\x1b[0m`);

  const [secretKey, publicKey] = await algorithm.generateKeyPair();
  const credentialId = crypto.randomBytes(32);
  const credentialIdEncoded = base64UrlEncode(credentialId);

  const publicKeyDer = getPublicKeyDer(publicKey.key, algorithm);
  const publicKeyAlgorithm = algorithm instanceof ES256 ? -7 : -257;

  let userId: UserId;
  if (typeof options.user.id === 'string') {
    userId = options.user.id;
  } else if (options.user.id instanceof Buffer) {
    userId = { data: options.user.id };
  } else if (options.user.id && typeof options.user.id === 'object' && 'data' in options.user.id) {
    userId = options.user.id as UserId;
  } else {
    throw new Error('Invalid user.id format');
  }

  await savePrivateKey(credentialId, rpId, secretKey, userId, publicKeyDer, publicKeyAlgorithm, userIdHash);

  console.log(`    Credential attestation completed with ID: \x1b[95m${credentialIdEncoded}\x1b[0m`);
  const uniqueId = createUniqueId(rpId, credentialIdEncoded);
  console.log(`    Passkey associated with credential created: \x1b[38;5;125m${uniqueId}\x1b[0m`);

  const authenticator: Authenticator = {
    aaguid: AAGUID,
    createAuthenticatorData: async (rpId: string, credentialId: Buffer, publicKey: PublicKey, algorithm: SigningAlgorithm): Promise<Buffer> => {
      const rpIdHash = sha256(Buffer.from(rpId));
      const flags = Buffer.from([0x45]);
      const signCount = Buffer.alloc(4);
      const aaguid = AAGUID;
      const credIdLength = Buffer.alloc(2);
      credIdLength.writeUInt16BE(credentialId.length, 0);
      const publicKeyBuffer = await algorithm.createCoseKey(publicKey);
      return Buffer.concat([rpIdHash, flags, signCount, aaguid, credIdLength, credentialId, publicKeyBuffer]);
    }
  };

  const authData = await authenticator.createAuthenticatorData(rpId, credentialId, publicKey, algorithm);

  const challenge = typeof options.challenge === 'string' ? options.challenge : base64UrlEncode(options.challenge.data);

  const clientData: CollectedClientData = {
    type: 'webauthn.create',
    challenge,
    origin: options.origin,
    crossOrigin: false
  };

  const clientDataJSON = Buffer.from(JSON.stringify(clientData));

  const attestationObject = await createAttestationObject(authData);

  return {
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
}

async function handleGetAssertion(options: PublicKeyCredentialRequestOptions): Promise<AuthenticatorAssertionResponse> {
  const storedCredential = await findCredential(options);

  const clientData: CollectedClientData = {
    type: 'webauthn.get',
    challenge: options.publicKey.challenge,
    origin: options.origin,
    crossOrigin: false
  };

  const clientDataJSON = Buffer.from(JSON.stringify(clientData));

  const [secretKey, algorithm, counter] = await loadPrivateKey(storedCredential.credentialId);
  const publicKey = crypto.createPublicKey(secretKey.key);

  const authenticator: Authenticator = {
    aaguid: AAGUID,
    createAuthenticatorData: async (rpId: string, credentialId: Buffer, publicKey: PublicKey, algorithm: SigningAlgorithm): Promise<Buffer> => {
      const rpIdHash = sha256(Buffer.from(rpId));
      const flags = Buffer.from([0x01]);  // UP=1
      const signCount = Buffer.alloc(4);
      signCount.writeUInt32BE(counter + 1, 0);  // Increment sign count
      return Buffer.concat([rpIdHash, flags, signCount]);
    }
  };

  const credentialIdBuffer = base64UrlDecode(storedCredential.credentialId);
  const authData = await authenticator.createAuthenticatorData(
    options.publicKey.rpId || storedCredential.rpId,
    credentialIdBuffer,
    { type: secretKey.type, key: publicKey },
    algorithm
  );

  const dataToSign = Buffer.concat([authData, sha256(clientDataJSON)]);
  const signature = await algorithm.sign(secretKey, dataToSign);

  await updateCredentialCounter(storedCredential.credentialId);

  console.log('\nAssertion created successfully.');

  const response: AuthenticatorAssertionResponse = {
    type: 'public-key',
    id: storedCredential.credentialId,
    rawId: storedCredential.credentialId,
    response: {
      clientDataJSON: base64UrlEncode(clientDataJSON),
      authenticatorData: base64UrlEncode(authData),
      signature: base64UrlEncode(signature),
      userHandle: storedCredential.userHandle ? base64UrlEncode(Buffer.from(storedCredential.userHandle, 'base64')) : null
    }
  };

  const assertionJsonString = JSON.stringify(response, null, 2);
  fs.writeFileSync('assertion.json', assertionJsonString);
  console.log('Assertion response saved to: assertion.json');

  return response;
}

async function main() {
  try {
    const util = require('util');
    const forceCreate = process.argv.includes('-force');
    const createInput = fs.readFileSync('create_options.json', 'utf-8');

    const createOptions = await parseCreateOptions(createInput);
    console.log('Parsed create options:\n');
    console.log(util.inspect(createOptions, { colors: true, depth: null, maxArrayLength: null, compact: false }));

    const createResponse = await createCredential(createOptions, forceCreate);

    if (createResponse) {
      if (createResponse.response.publicKey) {
        console.log('\nDER-encoded Public Key (ArrayBuffer):');
        console.log(createResponse.response.publicKey);
        const publicKeyDer = Buffer.from(createResponse.response.publicKey.split(', ').map(Number));
        const publicKey = crypto.createPublicKey({
          key: publicKeyDer,
          format: 'der',
          type: 'spki'
        });
        const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
        console.log('\n' + publicKeyPem.toString());

        console.log('Attestation ceremony completed.');

        fs.writeFileSync('public_key.pem', publicKeyPem);
        console.log('Public Key saved to: public_key.pem');
      } else {
        console.log('Public key not available in the response');
      }

      const jsonString = JSON.stringify(createResponse, null, 2);
      fs.writeFileSync('attestation.json', jsonString);
      console.log('Attestation response saved to: attestation.json');
    } else {
      console.log('No new data saved to attestation.json');
    }

    const getOptionsPath = 'get_options.json';

    if (!fs.existsSync(getOptionsPath) || fs.statSync(getOptionsPath).size === 0) {
      console.log('get_options.json is empty. Skipping assertion process.');
      return;
    }

    const getInput = fs.readFileSync(getOptionsPath, 'utf-8');
    console.log('\nProcessing assertion request...');

    const getOptions = await parseGetOptions(getInput);
    console.log('Parsed get options:\n');
    console.log(util.inspect(getOptions, { colors: true, depth: null, maxArrayLength: null, compact: false }));

    await handleGetAssertion(getOptions);
  } catch (error: unknown) {
    console.error('An error occurred:', error);
    if (error instanceof Error) {
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
    }
  }
}

main().catch((error) => {
  console.error('Unhandled error in main:', error);
  if (error instanceof Error) {
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
  }
});