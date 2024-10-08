import * as crypto from 'crypto';
import * as fs from 'fs';
import * as cbor from 'cbor';

import { 
  SecretKeyType,    // Enum for key types (ECDSA, RSA)
  SecretKey,        // Type for secret key object
  SigningAlgorithm, // Interface for signing algorithms
  ES256,            // ECDSA with P-256 curve (implements SigningAlgorithm)
  RS256,            // RSA with SHA-256 hash (implements SigningAlgorithm)
  base64UrlEncode,  // Encodes data to base64url
  base64UrlDecode   // Decodes base64url to data
} from './authn';

// Interfaces
export interface StoredCredential {
  credentialId: string;
  rpId: string;
  userIdHash: string;
  privateKey: string;
  userHandle: string;
  publicKey: string;
  publicKeyAlgorithm: number;
  counter: number;
}

export interface StoredCredentials {
  [uniqueId: string]: StoredCredential;
}

// Main functions
export async function savePrivateKey(
  credentialId: Buffer,
  rpId: string,
  secretKey: SecretKey,
  userId: string | { data: Buffer },
  publicKeyDer: Buffer,
  publicKeyAlgorithm: number,
  userIdHash: string
): Promise<void> {
  const coseKey = await createCoseKey(secretKey);
  const credentialIdEncoded = base64UrlEncode(credentialId);
  const uniqueId = createUniqueId(rpId, credentialIdEncoded);

  const userHandle = typeof userId === 'string' ? userId :
    Buffer.from(userId.data).toString('base64');

  const storedCredential: StoredCredential = {
    credentialId: credentialIdEncoded,
    rpId,
    userIdHash,
    privateKey: coseKey.toString('base64'),
    userHandle,
    publicKey: publicKeyDer.toString('base64'),
    publicKeyAlgorithm,
    counter: 0
  };

  let storedCredentials = readStoredCredentials();
  storedCredentials[uniqueId] = storedCredential;
  writeStoredCredentials(storedCredentials);
}

export async function updateCredentialCounter(credentialId: string): Promise<void> {
  const storedCredentials = readStoredCredentials();

  for (const uniqueId in storedCredentials) {
    if (storedCredentials[uniqueId].credentialId === credentialId) {
      storedCredentials[uniqueId].counter++;
      writeStoredCredentials(storedCredentials);
      return;
    }
  }

  throw new Error('Credential not found for updating counter');
}

export async function loadPrivateKey(credentialId: string): Promise<[SecretKey, SigningAlgorithm, number]> {
  const storedCredentials = readStoredCredentials();

  for (const uniqueId in storedCredentials) {
    const storedCredential = storedCredentials[uniqueId];
    if (storedCredential.credentialId === credentialId) {
      const coseKey = Buffer.from(base64UrlDecode(storedCredential.privateKey));
      const [secretKey, algorithm] = await coseKeyToSecretKey(coseKey);
      return [secretKey, algorithm, storedCredential.counter];
    }
  }

  throw new Error('Private key not found');
}

export async function findCredential(options: any): Promise<StoredCredential> {
  const rpId = (options.publicKey.rpId || options.rpId || '') as string;
  const storedCredentials = readStoredCredentials();

  console.log('\nStarting assertion process...\n');

  let matchingCredential: StoredCredential | null = null;
  let matchingUniqueId: string | null = null;

  if (options.publicKey.allowCredentials && options.publicKey.allowCredentials.length > 0) {
    for (const allowedCred of options.publicKey.allowCredentials) {
      if (typeof allowedCred.id === 'string') {
        const uniqueId = createUniqueId(rpId, allowedCred.id);
        console.log(`Requested passkey: \x1b[38;5;125m${uniqueId}\x1b[0m`);  // 256-color

        if (storedCredentials[uniqueId]) {
          matchingCredential = storedCredentials[uniqueId];
          matchingUniqueId = uniqueId;
          break;
        }
      }
    }
  } else {
    const matchingCredentials = Object.entries(storedCredentials).filter(([uniqueId, cred]) => cred.rpId === rpId);
    if (matchingCredentials.length > 0) {
      [matchingUniqueId, matchingCredential] = matchingCredentials[matchingCredentials.length - 1];
    }
  }

  if (matchingCredential && matchingUniqueId) {
    console.log(`Credential associated with uniqueId found:\n`);
    console.log(`    RP: \x1b[94m${matchingCredential.rpId}\x1b[0m`);
    console.log(`    ID: \x1b[95m${matchingCredential.credentialId}\x1b[0m`);

    return matchingCredential;
  }

  throw new Error('No matching credential found');
}

export function writeStoredCredentials(storedCredentials: StoredCredentials): void {
  fs.writeFileSync('stored_credentials.json', JSON.stringify(storedCredentials, null, 2));
}

export function readStoredCredentials(): StoredCredentials {
  if (fs.existsSync('stored_credentials.json')) {
    const fileContent = fs.readFileSync('stored_credentials.json', 'utf-8');
    if (fileContent.trim() !== '') {
      try {
        return JSON.parse(fileContent);
      } catch (error) {
        console.error('Error parsing stored_credentials.json:', error);
      }
    }
  }
  return {};
}

async function createCoseKey(secretKey: SecretKey): Promise<Buffer> {
  const privateKeyJwk = secretKey.key.export({ format: 'jwk' }) as any;

  switch (secretKey.type) {
    case SecretKeyType.Ecdsa:
      const coseKey = new Map();
      coseKey.set(1, 2); // kty: EC2
      coseKey.set(3, -7); // alg: ES256
      coseKey.set(-1, 1); // crv: P-256
      coseKey.set(-2, Buffer.from(privateKeyJwk.x, 'base64')); // x coordinate
      coseKey.set(-3, Buffer.from(privateKeyJwk.y, 'base64')); // y coordinate
      coseKey.set(-4, Buffer.from(privateKeyJwk.d, 'base64')); // private key
      return cbor.encode(coseKey);
    case SecretKeyType.Rsa:
      const rsaCoseKey = new Map();
      rsaCoseKey.set(1, 3); // kty: RSA
      rsaCoseKey.set(3, -257); // alg: RS256
      rsaCoseKey.set(-1, Buffer.from(privateKeyJwk.n, 'base64')); // modulus
      rsaCoseKey.set(-2, Buffer.from(privateKeyJwk.e, 'base64')); // public exponent
      rsaCoseKey.set(-3, Buffer.from(privateKeyJwk.d, 'base64')); // private exponent
      rsaCoseKey.set(-4, Buffer.from(privateKeyJwk.p, 'base64')); // prime1
      rsaCoseKey.set(-5, Buffer.from(privateKeyJwk.q, 'base64')); // prime2
      rsaCoseKey.set(-6, Buffer.from(privateKeyJwk.dp, 'base64')); // exponent1
      rsaCoseKey.set(-7, Buffer.from(privateKeyJwk.dq, 'base64')); // exponent2
      rsaCoseKey.set(-8, Buffer.from(privateKeyJwk.qi, 'base64')); // coefficient
      return cbor.encode(rsaCoseKey);
    default:
      throw new Error('Unsupported key type');
  }
}

async function coseKeyToSecretKey(coseKey: Buffer): Promise<[SecretKey, SigningAlgorithm]> {
  const coseKeyObj = cbor.decode(coseKey);
  const kty = coseKeyObj.get(1);

  switch (kty) {
    case 2: // EC2
      try {
        const d = coseKeyObj.get(-4);
        if (!d) throw new Error("EC private key not found in COSE key");
        const ecPrivateKey = crypto.createPrivateKey({
          key: {
            kty: 'EC',
            crv: 'P-256',
            x: base64UrlEncode(coseKeyObj.get(-2)),
            y: base64UrlEncode(coseKeyObj.get(-3)),
            d: base64UrlEncode(d)
          },
          format: 'jwk'
        });
        return [{ type: SecretKeyType.Ecdsa, key: ecPrivateKey }, new ES256()];
      } catch (error) {
        console.error("Error creating EC private key:", error);
        throw error;
      }
    case 3: // RSA
      try {
        const rsaPrivateKey = crypto.createPrivateKey({
          key: {
            kty: 'RSA',
            n: base64UrlEncode(coseKeyObj.get(-1)),
            e: base64UrlEncode(coseKeyObj.get(-2)),
            d: base64UrlEncode(coseKeyObj.get(-3)),
            p: base64UrlEncode(coseKeyObj.get(-4)),
            q: base64UrlEncode(coseKeyObj.get(-5)),
            dp: base64UrlEncode(coseKeyObj.get(-6)),
            dq: base64UrlEncode(coseKeyObj.get(-7)),
            qi: base64UrlEncode(coseKeyObj.get(-8))
          },
          format: 'jwk'
        });
        return [{ type: SecretKeyType.Rsa, key: rsaPrivateKey }, new RS256()];
      } catch (error) {
        console.error("Error creating RSA private key:", error);
        throw error;
      }
    default:
      throw new Error(`Unsupported key type: ${kty}`);
  }
}

export function generateUserIdHash(rpId: string, userId: string | { data: Buffer }): string {
  const userIdString = typeof userId === 'string' ? userId : base64UrlEncode(userId.data);
  const combinedString = `${rpId}:${userIdString}`;
  const hash = crypto.createHash('sha256').update(combinedString).digest();
  return base64UrlEncode(hash);
}

export function createUniqueId(rpId: string, credentialId: string): string {
  const combinedString = `${rpId}:${credentialId}`;
  const hash = crypto.createHash('sha256').update(combinedString).digest();
  return base64UrlEncode(hash);
}