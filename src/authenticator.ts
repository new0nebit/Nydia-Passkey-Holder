import { Ed25519, ES256, RS256, SigningAlgorithm } from './algorithms';
import { CBORValue, WebAuthnCBOR } from './cbor';
import { logDebug, logError, logInfo } from './logger';
import {
  createUniqueId,
  getAllCredentialsMetadata,
  getCredentialsMetadataByUniqueIds,
  getEncryptedRecord,
  openSecret,
  savePrivateKey,
  updateCredentialCounter,
} from './store';
import type { SecretPayload } from './store';
import {
  Account,
  AssertionResponse,
  AttestationResponse,
  CredentialCreationOptions,
  GetAssertionOptions,
  PublicKeyCredentialCreationOptions,
} from './types';
import { base64UrlDecode, base64UrlEncode } from './utils/base64url';
import { toArrayBuffer } from './utils/buffer';

type AttestationCborMap = CBORValue;

// Web Crypto API
const subtle = crypto.subtle;

// Authenticator Attestation GUID (AAGUID) for identifying the authenticator model.
const AAGUID: Uint8Array = new Uint8Array([
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x4E,
  0x79, 0x64, 0x69, 0x61
]);

// SHA-256 helper
async function sha256(data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
  return await subtle.digest('SHA-256', toArrayBuffer(data));
}

// Create random byte array of given size.
function generateRandomBytes(size: number): Uint8Array {
  const array = new Uint8Array(size);
  crypto.getRandomValues(array);
  return array;
}

// Build clientDataJSON containing WebAuthn operation type (create/get), challenge, and origin.
function createClientDataJSON(
  type: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string,
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

// Convert raw ECDSA signature to DER format.
function rawToDer(rawSignature: ArrayBuffer): ArrayBuffer {
  const raw = new Uint8Array(rawSignature);
  if (raw.length !== 64) {
    throw new Error('Invalid raw signature length');
  }

  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  // Prepend zero if the high bit is set (value >= 0x80)
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

  const totalLen = rLen + sLen + 4;
  const derSignature = new Uint8Array(totalLen + 2);

  let offset = 0;
  derSignature[offset++] = 0x30;
  derSignature[offset++] = totalLen;
  derSignature[offset++] = 0x02;
  derSignature[offset++] = rLen;
  derSignature.set(rDer, offset);
  offset += rLen;
  derSignature[offset++] = 0x02;
  derSignature[offset++] = sLen;
  derSignature.set(sDer, offset);

  return derSignature.buffer;
}

// Chooses a signing algorithm
function chooseAlgorithm(
  params: PublicKeyCredentialCreationOptions['pubKeyCredParams'],
): SigningAlgorithm {
  if (!params) {
    throw new Error('No supported algorithm found');
  }

  for (const param of params) {
    if (param.alg === -7) {
      return new ES256();
    }
    if (param.alg === -257) {
      return new RS256();
    }
    if (param.alg === -8) {
      return new Ed25519();
    }
  }
  throw new Error('No supported algorithm found');
}

// Load private key from stored credential and prepare it for signing
async function loadPrivateKey(
  uniqueId: string,
): Promise<[CryptoKey, SigningAlgorithm, SecretPayload]> {
  const secretPayload = await openSecret(uniqueId);
  const pkcs8 = new Uint8Array(base64UrlDecode(secretPayload.privateKey));

  let algorithmParams: EcKeyImportParams | RsaHashedImportParams | Algorithm;
  let signingAlgorithm: SigningAlgorithm;

  switch (secretPayload.publicKeyAlgorithm) {
    case -7:
      algorithmParams = { name: 'ECDSA', namedCurve: 'P-256' };
      signingAlgorithm = new ES256();
      break;
    case -257:
      algorithmParams = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      signingAlgorithm = new RS256();
      break;
    case -8:
      algorithmParams = { name: 'Ed25519' };
      signingAlgorithm = new Ed25519();
      break;
    default:
      throw new Error('Unsupported algorithm');
  }

  const privateKey = await subtle.importKey('pkcs8', pkcs8, algorithmParams, false, ['sign']);
  return [privateKey, signingAlgorithm, secretPayload];
}

// Convert buffer to hexadecimal string
function bufferToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Get algorithm name for logging
type AlgorithmName = 'ES256' | 'RS256' | 'Ed25519';

function getAlgorithmName(algorithm: SigningAlgorithm): AlgorithmName {
  if (algorithm instanceof ES256) return 'ES256';
  if (algorithm instanceof RS256) return 'RS256';
  return 'Ed25519';
}

async function resolveAllowedUniqueIds(
  rpId: string,
  allowCredentials?: PublicKeyCredentialDescriptor[],
): Promise<Set<string> | null> {
  if (!Array.isArray(allowCredentials) || allowCredentials.length === 0) {
    return null;
  }

  const uniqueIds = await Promise.all(
    allowCredentials.map(async (descriptor) => {
      const descriptorId = descriptor.id as string | ArrayBuffer | Uint8Array;
      const credentialId =
        typeof descriptorId === 'string'
          ? descriptorId
          : base64UrlEncode(toArrayBuffer(descriptorId));
      return createUniqueId(rpId, credentialId);
    }),
  );

  return new Set(uniqueIds);
}

// Create a new credential
export async function createCredential(
  options: CredentialCreationOptions,
): Promise<AttestationResponse> {
  logInfo('[Authenticator] Starting credential creation...');
  logDebug('[Authenticator] Options', options);

  try {
    if (!options.publicKey) {
      throw new Error('Missing publicKey property in options');
    }

    // Process options.publicKey.user.id
    const rawUserId = options.publicKey.user.id;

    let userIdLog: string;
    if (typeof rawUserId === 'string') {
      userIdLog = 'userId decoded from string';
    } else if (rawUserId instanceof ArrayBuffer) {
      userIdLog = 'userId is ArrayBuffer';
    } else if (rawUserId instanceof Uint8Array) {
      userIdLog = 'userId is Uint8Array';
    } else {
      throw new Error(`Invalid user.id type: ${Object.prototype.toString.call(rawUserId)}`);
    }

    const userId = toArrayBuffer(rawUserId);
    logDebug(`[Authenticator] ${userIdLog}`);

    // Determine rpId
    const rpId = options.publicKey.rpId || options.publicKey.rp.id;
    if (!rpId) {
      throw new Error('rpId is missing in credential creation options');
    }
    logDebug('[Authenticator] rpId', rpId);

    // Choose a signing algorithm
    const algorithm = chooseAlgorithm(options.publicKey.pubKeyCredParams);
    logDebug('[Authenticator] Chosen algorithm', getAlgorithmName(algorithm));

    // Check excludeCredentials
    const excludeList = options.publicKey.excludeCredentials ?? [];
    for (const descriptor of excludeList) {
      const descriptorId = base64UrlEncode(toArrayBuffer(descriptor.id as ArrayBuffer));
      const uniqueId = await createUniqueId(rpId, descriptorId);
      if (await getEncryptedRecord(uniqueId)) {
        logDebug('[Authenticator] excludeCredentials match found - aborting creation', { rpId, credentialId: descriptorId, uniqueId });
        throw new DOMException('A passkey for this account already exists.', 'InvalidStateError');
      }
    }

    // Generate key pair
    logDebug('[Authenticator] Generating key pair for algorithm', getAlgorithmName(algorithm));
    const keyPair = await algorithm.generateKeyPair();
    logDebug('[Authenticator] Key pair generated successfully');

    // Generate credential ID
    const credentialId = generateRandomBytes(32);
    const credentialIdEncoded = base64UrlEncode(credentialId);
    logDebug('[Authenticator] Credential ID generated', credentialIdEncoded);

    // Determine COSE algorithm identifier
    let publicKeyAlgorithm: number;
    if (algorithm instanceof ES256) {
      publicKeyAlgorithm = -7;
    } else if (algorithm instanceof RS256) {
      publicKeyAlgorithm = -257;
    } else {
      publicKeyAlgorithm = -8;
    }
    logDebug('[Authenticator] Public key algorithm', publicKeyAlgorithm);

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
      // Ed25519
      const jwk = await subtle.exportKey('jwk', keyPair.publicKey);
      const x = base64UrlDecode(jwk.x!);
      cosePublicKey = WebAuthnCBOR.createOKPCOSEKey(x, publicKeyAlgorithm);
    }

    // Export public key in DER format
    const publicKeyDER = await subtle.exportKey('spki', keyPair.publicKey);
    logDebug('[Authenticator] Public key exported in DER format');
    const publicKeyDERBase64 = base64UrlEncode(publicKeyDER);

    // Save the private key
    const uniqueId = await savePrivateKey(
      credentialId,
      rpId,
      keyPair.privateKey,
      new Uint8Array(userId),
      publicKeyAlgorithm,
      options.publicKey.user.name, // Pass the username
    );
    logDebug('[Authenticator] Private key saved');
    logDebug('[Authenticator] UniqueId associated with credential created', uniqueId);

    // Create authenticator data
    const rpIdHash = new Uint8Array(await sha256(new TextEncoder().encode(rpId)));
    const flags = 0x45; // UP=1 (User Present), UV=1 (User Verified), AT=1 (Attested Credential Data)
    const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x00]); // Initial sign count
    const credentialIdLengthBytes = new Uint8Array([
      (credentialId.length >> 8) & 0xff,
      credentialId.length & 0xff,
    ]);

    const authenticatorData = new Uint8Array(
      rpIdHash.length +
        1 +
        signCount.length +
        AAGUID.length +
        credentialIdLengthBytes.length +
        credentialId.length +
        cosePublicKey.length,
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

    authenticatorData.set(credentialIdLengthBytes, offset);
    offset += credentialIdLengthBytes.length;

    authenticatorData.set(credentialId, offset);
    offset += credentialId.length;

    authenticatorData.set(cosePublicKey, offset);

    logDebug('[Authenticator] Authenticator data created');

    // Create clientDataJSON
    const clientDataJSON = createClientDataJSON(
      'webauthn.create',
      base64UrlEncode(options.publicKey.challenge),
      options.origin,
    );
    logDebug('[Authenticator] Client data JSON created');

    // Build attestationObject as a Map (not a plain object).
    // Our CBOR encoder sorts map keys by the bytewise lexicographic order of
    // their CBOR encodings (RFC 8949 §4.2.1), which matches CTAP2’s canonical
    // CBOR expectations for string keys. For "fmt", "attStmt", and "authData",
    // this yields the required key order "fmt" → "attStmt" → "authData".
    const attestationMap = new Map<string, AttestationCborMap>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authenticatorData],
    ]);
    const attestationObject = WebAuthnCBOR.encode(attestationMap);
    logDebug('[Authenticator] Attestation object created');

    // Construct the response
    const createResponse: AttestationResponse = {
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

    logInfo('[Authenticator] Credential created successfully');
    logDebug('[Authenticator] Attestation response', createResponse);

    return createResponse;
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    if (!(error instanceof DOMException && error.name === 'InvalidStateError')) {
      logError(`[Authenticator] Error in createCredential: ${errorMessage}`, error);
    }
    throw error;
  }
}

// Sign the challenge using the credential identified by selectedUniqueId
export async function handleGetAssertion(
  options: GetAssertionOptions,
  selectedUniqueId: string,
): Promise<AssertionResponse> {
  logInfo('[Authenticator] Starting assertion handling...');
  logDebug('[Authenticator] Assertion options', options);

  // Check for the presence of the challenge
  if (!options.publicKey || !options.publicKey.challenge) {
    throw new Error('Challenge is missing in the options');
  }

  // Decode the challenge
  let challengeBuffer: Uint8Array;
  let challengeString: string;

  if (typeof options.publicKey.challenge === 'string') {
    // Challenge as base64url string
    challengeBuffer = new Uint8Array(toArrayBuffer(options.publicKey.challenge));
    challengeString = options.publicKey.challenge;
  } else {
    // Challenge as binary (ArrayBuffer or Uint8Array)
    challengeBuffer = new Uint8Array(toArrayBuffer(options.publicKey.challenge));
    challengeString = base64UrlEncode(challengeBuffer);
  }

  logDebug('[Authenticator] Challenge buffer (hex)', bufferToHex(challengeBuffer));
  logDebug('[Authenticator] Challenge string', challengeString);

  // Determine rpId
  const rpId = options.publicKey.rpId;
  if (!rpId) {
    throw new Error('rpId is missing in assertion options');
  }
  logDebug('[Authenticator] Using rpId', rpId);

  const allowedUniqueIds = await resolveAllowedUniqueIds(rpId, options.publicKey.allowCredentials);
  if (allowedUniqueIds && !allowedUniqueIds.has(selectedUniqueId)) {
    throw new DOMException('Selected credential is not allowed for this request', 'NotAllowedError');
  }

  // Load private key, algorithm, and secret payload
  const [privateKey, algorithm, secretPayload] = await loadPrivateKey(selectedUniqueId);

  logDebug('[Authenticator] Loaded private key', {
    alg: secretPayload.publicKeyAlgorithm,
    counter: secretPayload.counter,
  });

  // Form authenticatorData
  const rpIdHash = new Uint8Array(await sha256(new TextEncoder().encode(rpId)));
  logDebug('[Authenticator] Computed rpIdHash (hex)', bufferToHex(rpIdHash));

  const flags = new Uint8Array([0x05]); // UP=1 (User Present), UV=1 (User Verified)
  const signCount = new Uint8Array(4);
  const dataView = new DataView(signCount.buffer);
  dataView.setUint32(0, secretPayload.counter + 1, false); // Big-endian

  const authenticatorData = new Uint8Array(rpIdHash.length + flags.length + signCount.length);

  let offset = 0;
  authenticatorData.set(rpIdHash, offset);
  offset += rpIdHash.length;

  authenticatorData.set(flags, offset);
  offset += flags.length;

  authenticatorData.set(signCount, offset);

  logDebug('[Authenticator] Constructed authenticatorData (hex)', bufferToHex(authenticatorData));

  // Create clientDataJSON
  const clientDataJSON = createClientDataJSON('webauthn.get', challengeString, options.origin);
  logDebug(
    '[Authenticator] Constructed clientDataJSON',
    JSON.parse(new TextDecoder().decode(clientDataJSON)),
  );

  // Calculate clientDataHash
  const clientDataHash = new Uint8Array(await sha256(clientDataJSON));
  logDebug('[Authenticator] Computed clientDataHash (hex)', bufferToHex(clientDataHash));

  // Form signatureBase
  const signatureBase = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signatureBase.set(authenticatorData, 0);
  signatureBase.set(clientDataHash, authenticatorData.length);

  logDebug('[Authenticator] Constructed signatureBase (hex)', bufferToHex(signatureBase));

  // Generate signature based on algorithm
  let signature: ArrayBuffer;

  if (algorithm instanceof ES256) {
    // Generate raw signature
    const rawSignature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      signatureBase,
    );
    logDebug('[Authenticator] Generated signature using ES256 (raw format)');

    // Convert raw signature to DER format
    signature = rawToDer(rawSignature);
    logDebug('[Authenticator] Converted signature to DER format');

    const signatureBytes = new Uint8Array(signature);
    logDebug('[Authenticator] Signature length after DER conversion', signatureBytes.length);
    logDebug('[Authenticator] Signature (DER hex)', bufferToHex(signatureBytes));

    // Check if signature is DER-encoded
    const firstByte = signatureBytes[0];
    logDebug('[Authenticator] First byte of ECDSA signature (hex)', firstByte.toString(16));

    if (firstByte === 0x30) {
      logDebug('[Authenticator] Signature appears to be DER-encoded');
    } else {
      logDebug('[Authenticator] Signature does not appear to be DER-encoded');
    }
  } else if (algorithm instanceof RS256) {
    signature = await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, privateKey, signatureBase);
    logDebug('[Authenticator] Generated signature using RS256');

    const signatureBytes = new Uint8Array(signature);
    logDebug('[Authenticator] Signature length', signatureBytes.length);
    logDebug('[Authenticator] Signature (hex)', bufferToHex(signatureBytes));
  } else {
    signature = await subtle.sign({ name: 'Ed25519' }, privateKey, signatureBase);
    logDebug('[Authenticator] Generated signature using Ed25519');

    const signatureBytes = new Uint8Array(signature);
    logDebug('[Authenticator] Signature length', signatureBytes.length);
    logDebug('[Authenticator] Signature (hex)', bufferToHex(signatureBytes));
  }

  logDebug('[Authenticator] Signature (base64url)', base64UrlEncode(signature));

  // Update credential counter
  await updateCredentialCounter(selectedUniqueId);

  // Construct the response
  const response: AssertionResponse = {
    type: 'public-key',
    id: secretPayload.credentialId,
    rawId: secretPayload.credentialId,
    response: {
      clientDataJSON: base64UrlEncode(clientDataJSON),
      authenticatorData: base64UrlEncode(authenticatorData),
      signature: base64UrlEncode(signature),
      userHandle: secretPayload.userHandle || null,
    },
  };

  logDebug('[Authenticator] Assertion response', response);

  return response;
}

// Return available credentials matching the relying party ID
export async function getAvailableCredentials(
  rpId: string,
  allowCredentialIds?: string[],
): Promise<Account[]> {
  const filtered =
    Array.isArray(allowCredentialIds) && allowCredentialIds.length > 0
      ? await getCredentialsMetadataByUniqueIds(
          await Promise.all(
            allowCredentialIds.map(async (credentialId) => createUniqueId(rpId, credentialId)),
          ),
        )
      : (await getAllCredentialsMetadata()).filter((metadata) => metadata.rpId === rpId);

  return filtered.map((metadata) => ({
    username: metadata.userName || 'Unknown user',
    uniqueId: metadata.uniqueId,
    creationTime: metadata.creationTime,
  }));
}
