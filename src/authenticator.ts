import { WebAuthnCBOR } from './cbor';
import { ES256, RS256, SigningAlgorithm } from './algorithms';
import {
  createUniqueId,
  savePrivateKey,
  loadPrivateKey,
  findCredential,
  updateCredentialCounter,
  getMemoryStore,
  getAllStoredCredentials,
} from './store';
import { Account } from './types';
import { logInfo, logError } from './logger';
import { base64UrlEncode, base64UrlDecode } from './base64url';

// Web Crypto API
const crypto = self.crypto;
const subtle = crypto.subtle;

// Authenticator Attestation GUID (AAGUID) for identifying the authenticator model
const AAGUID: Uint8Array = new Uint8Array([
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x4E,
  0x79, 0x64, 0x69, 0x61
]);

function logAuth(message: string, data?: any): void {
  if (data !== undefined) {
    console.log(`[Authenticator] ${message}:`, data);
  } else {
    console.log(`[Authenticator] ${message}`);
  }
}

/* ================================================
   Helper Functions
================================================ */

/**
 * Computes SHA-256 hash of the given data.
 * @param data - The data to hash.
 * @returns A Promise that resolves to the hash as an ArrayBuffer.
 */
async function sha256(data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
  const buffer = data instanceof ArrayBuffer ? data : data.buffer;
  return await subtle.digest('SHA-256', buffer);
}

/**
 * Generates a random byte array of the given size.
 * @param size - The number of bytes to generate.
 * @returns A Uint8Array containing random bytes.
 */
function generateRandomBytes(size: number): Uint8Array {
  const array = new Uint8Array(size);
  crypto.getRandomValues(array);
  return array;
}

/**
 * Creates the clientDataJSON used in WebAuthn operations.
 * @param type - The operation type ('webauthn.create' or 'webauthn.get').
 * @param challenge - The challenge string.
 * @param origin - The origin string.
 * @returns The clientDataJSON as an ArrayBuffer.
 */
function createClientDataJSON(
  type: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string
): ArrayBuffer {
  const clientData = {
    type,
    challenge,
    origin,
    crossOrigin: false,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
  return clientDataJSON.buffer;
}

/**
 * Converts a raw ECDSA signature to DER format.
 * @param rawSignature - The raw signature as an ArrayBuffer.
 * @returns The DER-encoded signature as an ArrayBuffer.
 */
function rawToDer(rawSignature: ArrayBuffer): ArrayBuffer {
  const raw = new Uint8Array(rawSignature);
  if (raw.length !== 64) {
    throw new Error('Invalid raw signature length');
  }

  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  // Prepend zero if the first byte is greater than 0x80
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

  let offset = 0;
  derSignature[offset++] = 0x30; // SEQUENCE tag
  derSignature[offset++] = totalLen;
  derSignature[offset++] = 0x02; // INTEGER tag for r
  derSignature[offset++] = rLen;
  derSignature.set(rDer, offset);
  offset += rLen;
  derSignature[offset++] = 0x02; // INTEGER tag for s
  derSignature[offset++] = sLen;
  derSignature.set(sDer, offset);

  return derSignature.buffer;
}

/**
 * Chooses a supported signing algorithm from the provided parameters.
 * @param params - An array of public key credential parameters.
 * @returns An instance of a supported SigningAlgorithm.
 */
function chooseAlgorithm(params: any[]): SigningAlgorithm {
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

/**
 * Converts a buffer to a hexadecimal string.
 * @param buffer - The buffer to convert.
 * @returns The hexadecimal representation of the buffer.
 */
function bufferToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/* ================================================
   Main Functions
================================================ */

/**
 * Handles the creation of a new credential.
 * @param options - The options provided for credential creation.
 * @returns A Promise that resolves to the credential response.
 */
export async function createCredential(options: any): Promise<any> {
  logAuth('Starting credential creation...');
  logAuth('Options:', options);

  try {
    // Check for options.publicKey
    if (!options.publicKey) {
      throw new Error('Missing publicKey property in options');
    }

    // Process options.publicKey.user.id
    let userId: ArrayBuffer;
    if (typeof options.publicKey.user.id === 'string') {
      userId = base64UrlDecode(options.publicKey.user.id).buffer;
      logAuth('userId decoded from string');
    } else if (options.publicKey.user.id instanceof ArrayBuffer) {
      userId = options.publicKey.user.id;
      logAuth('userId is ArrayBuffer');
    } else if (ArrayBuffer.isView(options.publicKey.user.id)) {
      userId = options.publicKey.user.id.buffer.slice(
        options.publicKey.user.id.byteOffset,
        options.publicKey.user.id.byteOffset + options.publicKey.user.id.byteLength
      );
      logAuth('userId is ArrayBufferView');
    } else {
      logAuth(`Invalid user.id type: ${typeof options.publicKey.user.id}`);
      throw new Error('Invalid user.id type');
    }

    // Determine rpId
    const rpId = options.publicKey.rpId || options.publicKey.rp.id || new URL(options.origin).hostname;
    logAuth('rpId:', rpId);

    // Choose a signing algorithm
    const algorithm = chooseAlgorithm(options.publicKey.pubKeyCredParams);
    logAuth('Chosen algorithm:', algorithm instanceof ES256 ? 'ES256' : 'RS256');

    // Hash the user ID
    const userIdHashBuffer = new Uint8Array(await sha256(userId));
    const userIdHash = base64UrlEncode(userIdHashBuffer);
    logAuth('userIdHash generated:', userIdHash);

    // Check for existing credentials
    const storedCredentials = await getAllStoredCredentials();
    const existingCredential = storedCredentials.find(
      (cred) => cred.userIdHash === userIdHash
    );

    if (existingCredential) {
      logAuth(
        `Existing credential found for user ${options.publicKey.user.name} and RP ${rpId}`
      );
      return null;
    }

    // Generate key pair
    logAuth(
      'Generating key pair for algorithm:',
      algorithm instanceof ES256 ? 'ES256' : 'RS256'
    );
    const keyPair = await algorithm.generateKeyPair();
    logAuth('Key pair generated successfully');

    // Generate credential ID
    const credentialId = generateRandomBytes(32);
    const credentialIdEncoded = base64UrlEncode(credentialId);
    logAuth('Credential ID generated:', credentialIdEncoded);

    // Determine public key algorithm identifier
    const publicKeyAlgorithm = algorithm instanceof ES256 ? -7 : -257;
    logAuth('Public key algorithm:', publicKeyAlgorithm);

    // Create COSE public key
    let cosePublicKey: Uint8Array;
    if (algorithm instanceof ES256) {
      const jwk = await subtle.exportKey('jwk', keyPair.publicKey);
      const x = base64UrlDecode(jwk.x!);
      const y = base64UrlDecode(jwk.y!);
      cosePublicKey = WebAuthnCBOR.createEC2COSEKey(x, y, publicKeyAlgorithm);
    } else if (algorithm instanceof RS256) {
      const jwk = await subtle.exportKey('jwk', keyPair.publicKey);
      const n = base64UrlDecode(jwk.n!);
      const e = base64UrlDecode(jwk.e!);
      cosePublicKey = WebAuthnCBOR.createRSACOSEKey(n, e, publicKeyAlgorithm);
    } else {
      throw new Error('Unsupported algorithm');
    }

    // Export public key in DER format
    const publicKeyDER = await subtle.exportKey('spki', keyPair.publicKey);
    logAuth('Public key exported in DER format');
    const publicKeyDERBase64 = base64UrlEncode(publicKeyDER);

    // Save the private key
    await savePrivateKey(
      credentialId,
      rpId,
      keyPair.privateKey,
      new Uint8Array(userId),
      cosePublicKey,
      publicKeyAlgorithm,
      userIdHash,
      options.publicKey.user.name // Pass the username
    );
    logAuth('Private key saved');

    // Create a unique ID associated with the credential
    const uniqueId = await createUniqueId(rpId, credentialIdEncoded);
    logAuth('UniqueId associated with credential created:', uniqueId);

    // Create authenticator data
    const rpIdHash = new Uint8Array(
      await sha256(new TextEncoder().encode(rpId))
    );
    const flags = 0x45; // UP=1 (User Present), UV=1 (User Verified), AT=1 (Attested Credential Data Present)
    const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x00]); // Initial sign count
    const credentialIdLength = new Uint8Array([
      (credentialId.length >> 8) & 0xff,
      credentialId.length & 0xff,
    ]);

    const authenticatorData = new Uint8Array(
      rpIdHash.length +
        1 +
        signCount.length +
        AAGUID.length +
        credentialIdLength.length +
        credentialId.length +
        cosePublicKey.length
    );

    // Construct authenticator data
    let offset = 0;
    authenticatorData.set(rpIdHash, offset);
    offset += rpIdHash.length;

    authenticatorData[offset++] = flags;

    authenticatorData.set(signCount, offset);
    offset += signCount.length;

    authenticatorData.set(AAGUID, offset);
    offset += AAGUID.length;

    authenticatorData.set(credentialIdLength, offset);
    offset += credentialIdLength.length;

    authenticatorData.set(credentialId, offset);
    offset += credentialId.length;

    authenticatorData.set(cosePublicKey, offset);

    logAuth('Authenticator data created');

    // Create clientDataJSON
    const clientDataJSON = createClientDataJSON(
      'webauthn.create',
      base64UrlEncode(options.publicKey.challenge),
      options.origin
    );
    logAuth('Client data JSON created');

    // Encode attestation object
    const attestationObject = WebAuthnCBOR.encode({
      fmt: 'none',
      authData: authenticatorData,
      attStmt: {},
    });
    logAuth('Attestation object created');

    // Construct the response
    const createResponse = {
      type: 'public-key',
      id: credentialIdEncoded,
      rawId: credentialIdEncoded,
      response: {
        clientDataJSON: base64UrlEncode(clientDataJSON),
        attestationObject: base64UrlEncode(attestationObject),
        authenticatorData: base64UrlEncode(authenticatorData),
        publicKeyAlgorithm,
        publicKeyDER: publicKeyDERBase64,
      },
    };

    logAuth('Credential created successfully');
    logAuth('Credential:', createResponse);

    // Save attestation response in memory
    const memoryStore = getMemoryStore();
    memoryStore.saveAttestationResponse(createResponse);
    logAuth('Attestation response saved to MemoryStore');

    return createResponse;
  } catch (error: any) {
    logError(`Error in createCredential: ${error.message}`, error);
    throw error;
  }
}

/**
 * Handles the get assertion operation.
 * @param options - The options provided for assertion.
 * @param selectedCredentialId - The ID of the selected credential (optional).
 * @returns A Promise that resolves to the assertion response.
 */
export async function handleGetAssertion(
  options: any,
  selectedCredentialId?: string
): Promise<any> {
  logAuth('Starting assertion handling...');
  logAuth('Assertion options:', options);

  // Check for the presence of the challenge
  if (!options.publicKey || !options.publicKey.challenge) {
    throw new Error('Challenge is missing in the options');
  }

  // Decode the challenge
  let challengeBuffer: Uint8Array;
  let challengeString: string;

  if (typeof options.publicKey.challenge === 'string') {
    // Challenge as base64url string
    challengeBuffer = base64UrlDecode(options.publicKey.challenge);
    challengeString = options.publicKey.challenge;
  } else {
    // Challenge as ArrayBuffer
    challengeBuffer = new Uint8Array(options.publicKey.challenge);
    challengeString = base64UrlEncode(challengeBuffer);
  }

  logAuth('Challenge buffer (hex):', bufferToHex(challengeBuffer));
  logAuth('Challenge string:', challengeString);

  // Search for stored credentials
  const storedCredential = await findCredential(
    options.publicKey,
    selectedCredentialId
  );

  if (!storedCredential) {
    throw new Error('No matching credential found');
  }

  // Determine rpId
  const rpId = options.publicKey.rpId || new URL(options.origin).hostname;
  logAuth('Using rpId:', rpId);

  // Load private key and algorithm
  const [secretKey, algorithm, counter] = await loadPrivateKey(
    storedCredential.credentialId
  );

  logAuth('Loaded private key and algorithm:', {
    secretKeyType: secretKey.type,
    algorithmName: algorithm instanceof ES256 ? 'ES256' : 'RS256',
    counter,
  });

  // Form authenticatorData
  const rpIdHash = new Uint8Array(
    await sha256(new TextEncoder().encode(rpId))
  );
  logAuth('Computed rpIdHash (hex):', bufferToHex(rpIdHash));

  const flags = new Uint8Array([0x05]); // UP=1 (User Present), UV=1 (User Verified)
  const signCount = new Uint8Array(4);
  const dataView = new DataView(signCount.buffer);
  dataView.setUint32(0, counter + 1, false); // Big-endian

  const authenticatorData = new Uint8Array(
    rpIdHash.length + flags.length + signCount.length
  );

  // Construct authenticator data
  let offset = 0;
  authenticatorData.set(rpIdHash, offset);
  offset += rpIdHash.length;

  authenticatorData.set(flags, offset);
  offset += flags.length;

  authenticatorData.set(signCount, offset);

  logAuth(
    'Constructed authenticatorData (hex):',
    bufferToHex(authenticatorData)
  );

  // Create clientDataJSON
  const clientDataJSON = createClientDataJSON(
    'webauthn.get',
    challengeString,
    options.origin
  );
  logAuth(
    'Constructed clientDataJSON:',
    JSON.parse(new TextDecoder().decode(clientDataJSON))
  );

  // Calculate clientDataHash
  const clientDataHash = new Uint8Array(await sha256(clientDataJSON));
  logAuth('Computed clientDataHash (hex):', bufferToHex(clientDataHash));

  // Form signatureBase
  const signatureBase = new Uint8Array(
    authenticatorData.length + clientDataHash.length
  );
  signatureBase.set(authenticatorData, 0);
  signatureBase.set(clientDataHash, authenticatorData.length);

  logAuth('Constructed signatureBase (hex):', bufferToHex(signatureBase));

  // Generate signature
  let signature: ArrayBuffer;

  if (algorithm instanceof ES256) {
    // Generate raw signature
    const rawSignature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      secretKey,
      signatureBase
    );
    logAuth('Generated signature using ES256 (raw format)');

    // Convert raw signature to DER format
    signature = rawToDer(rawSignature);
    logAuth('Converted signature to DER format');

    // Log signature details
    const signatureBytes = new Uint8Array(signature);
    logAuth(
      'Signature length after DER conversion:',
      signatureBytes.length
    );
    logAuth('Signature (DER hex):', bufferToHex(signatureBytes));

    // Check if signature is DER-encoded
    const firstByte = signatureBytes[0];
    logAuth('First byte of ECDSA signature (hex):', firstByte.toString(16));

    if (firstByte === 0x30) {
      logAuth('Signature appears to be DER-encoded');
    } else {
      logAuth('Signature does not appear to be DER-encoded');
    }
  } else if (algorithm instanceof RS256) {
    // Generate signature
    signature = await subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      secretKey,
      signatureBase
    );
    logAuth('Generated signature using RS256');

    // Log signature details
    const signatureBytes = new Uint8Array(signature);
    logAuth('Signature length:', signatureBytes.length);
    logAuth('Signature (hex):', bufferToHex(signatureBytes));
  } else {
    throw new Error('Unsupported algorithm');
  }

  logAuth('Signature (base64url):', base64UrlEncode(signature));

  // Update credential counter
  await updateCredentialCounter(storedCredential.credentialId);

  // Construct the response
  const response = {
    type: 'public-key',
    id: storedCredential.credentialId,
    rawId: storedCredential.credentialId,
    response: {
      clientDataJSON: base64UrlEncode(clientDataJSON),
      authenticatorData: base64UrlEncode(authenticatorData),
      signature: base64UrlEncode(signature),
      userHandle: storedCredential.userHandle || null,
    },
  };

  logAuth('Constructed assertion response:', response);

  return response;
}

/**
 * Retrieves available credentials for a given RP ID.
 * @param rpId - The relying party ID.
 * @returns A Promise that resolves to an array of Account objects.
 */
export async function getAvailableCredentials(
  rpId: string
): Promise<Account[]> {
  const storedCredentials = await getAllStoredCredentials();
  const accounts: Account[] = [];

  for (const cred of storedCredentials) {
    if (cred.rpId === rpId) {
      accounts.push({
        username: cred.userName || 'Unknown user',
        userHandle: cred.userHandle,
        credentialId: cred.credentialId,
        uniqueId: cred.uniqueId,
      });
    }
  }

  return accounts;
}

/**
 * Initializes the authenticator by loading stored credentials.
 */
export function initializeAuthenticator(): void {
  try {
    logInfo('Initializing WebAuthn authenticator...');
    getAllStoredCredentials()
      .then((storedCredentials) => {
        logInfo(`Found ${storedCredentials.length} stored credentials`);
        logInfo('WebAuthn authenticator initialized successfully');
      })
      .catch((error) => {
        logError(
          'Error retrieving stored credentials during initialization',
          error
        );
      });
  } catch (error) {
    logError('Error during authenticator initialization', error);
    throw error;
  }
}
