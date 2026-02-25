import { Ed25519, ES256, RS256, SigningAlgorithm } from './algorithms';
import { logDebug, logError, logWarn } from './logger';
import { uploadPasskeyDirect } from './sia';
import {
  BackgroundMessage,
  CredentialMetadata,
  EncryptedEnvelope,
  EncryptedRecord,
  GetAssertionOptions,
  RenterdSettings,
  SerializedCredentialDescriptor,
  SerializedRequestOptions,
  StoredCredential,
} from './types';
import { base64UrlDecode, base64UrlEncode } from './utils/base64url';

// Web Crypto API
const subtle = crypto.subtle;

// Simple per-credential mutex to avoid race conditions during counter updates
const counterLocks: Map<string, Promise<void>> = new Map();

type FindCredentialOptions = SerializedRequestOptions | GetAssertionOptions;

// Helper function to extract rpId from various option formats
function extractRpId(options: FindCredentialOptions): string | undefined {
  if (!options || typeof options !== 'object') return undefined;

  const opts = options as { publicKey?: unknown; origin?: string };
  if (!opts.publicKey || typeof opts.publicKey !== 'object') {
    // Fallback to origin
    return opts.origin ? new URL(opts.origin).hostname : undefined;
  }

  const publicKey = opts.publicKey as { rpId?: string; rp?: { id?: string } };
  return publicKey.rpId ?? publicKey.rp?.id ?? (opts.origin ? new URL(opts.origin).hostname : undefined);
}

// Helper function to normalize credential ID to string
function normalizeCredentialId(id: unknown): string | undefined {
  if (typeof id === 'string') return id;
  if (id instanceof ArrayBuffer) return base64UrlEncode(new Uint8Array(id));
  if (id instanceof Uint8Array) return base64UrlEncode(id);
  return undefined;
}

// IndexedDB
const DB_NAME = 'NydiaDB';
const DB_VERSION = 4;
export const STORE_NAME = 'storedCredentials';
export const SETTINGS_STORE = 'settings';

function setupStores(db: IDBDatabase) {
  if (!db.objectStoreNames.contains(STORE_NAME)) {
    db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
  }
  if (!db.objectStoreNames.contains(SETTINGS_STORE)) {
    db.createObjectStore(SETTINGS_STORE, { keyPath: 'id' });
  }
}

export function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => setupStores(request.result);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Failed to open IndexedDB'));
  });
}

// rootKey (HKDF)
let rootKey: CryptoKey | null = null;

const HKDF_METADATA_INFO = new TextEncoder().encode('metadata:v1');
const HKDF_SECRET_INFO = new TextEncoder().encode('secret:v1');

async function loadRootKeyFromDB(): Promise<CryptoKey | null> {
  if (rootKey) return rootKey;

  const db = await openDB();
  const rootKeyEntry = await new Promise<{ key?: CryptoKey } | undefined>((resolve) => {
    db
      .transaction(SETTINGS_STORE, 'readonly')
      .objectStore(SETTINGS_STORE)
      .get('rootKey').onsuccess = (event) =>
        resolve((event.target as IDBRequest<{ key?: CryptoKey }>).result);
  });

  if (rootKeyEntry?.key) {
    rootKey = rootKeyEntry.key;
    logDebug('[Store] rootKey loaded');
  }
  return rootKey;
}

async function getRootKey(): Promise<CryptoKey> {
  const key = await loadRootKeyFromDB();
  if (key) return key;
  throw new Error('rootKeyMissing');
}

export async function getRootKeyIfAvailable(): Promise<CryptoKey | null> {
  return loadRootKeyFromDB();
}

// Background-only: stores rootKey in IndexedDB
export async function setRootKey(key: CryptoKey): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(SETTINGS_STORE, 'readwrite')
      .objectStore(SETTINGS_STORE)
      .put({ id: 'rootKey', key }).onsuccess = () => resolve();
  });
  rootKey = key;
  logDebug('[Store] rootKey persisted');
}

// HKDF key derivation
async function deriveAesKey(info: Uint8Array): Promise<CryptoKey> {
  const root = await getRootKey();
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0) as BufferSource, info: info as BufferSource },
    root,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function deriveMetadataKey(): Promise<CryptoKey> {
  return deriveAesKey(HKDF_METADATA_INFO);
}

function deriveSecretKey(): Promise<CryptoKey> {
  return deriveAesKey(HKDF_SECRET_INFO);
}

// encrypt / decrypt helpers
async function sealEnvelope(key: CryptoKey, payload: Record<string, unknown>): Promise<EncryptedEnvelope> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  return {
    iv: base64UrlEncode(iv),
    data: base64UrlEncode(new Uint8Array(ciphertext)),
  };
}

async function openEnvelope<T>(key: CryptoKey, envelope: EncryptedEnvelope): Promise<T> {
  const iv = new Uint8Array(base64UrlDecode(envelope.iv));
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    new Uint8Array(base64UrlDecode(envelope.data)),
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as T;
}

async function encryptCredential(credential: StoredCredential): Promise<EncryptedRecord> {
  const [metadataKey, secretKey] = await Promise.all([deriveMetadataKey(), deriveSecretKey()]);

  const [metadata, secret] = await Promise.all([
    sealEnvelope(metadataKey, {
      rpId: credential.rpId,
      userName: credential.userName,
      creationTime: credential.creationTime,
    }),
    sealEnvelope(secretKey, {
      credentialId: credential.credentialId,
      userHandle: credential.userHandle,
      publicKeyAlgorithm: credential.publicKeyAlgorithm,
      privateKey: credential.privateKey,
      counter: credential.counter,
    }),
  ]);

  return {
    uniqueId: credential.uniqueId,
    metadata,
    secret,
    isSynced: credential.isSynced,
  };
}

type MetadataPayload = { rpId: string; userName?: string; creationTime: number };
type SecretPayload = {
  credentialId: string;
  userHandle: string;
  publicKeyAlgorithm: number;
  counter: number;
  privateKey: string;
};

async function decryptCredential(record: EncryptedRecord): Promise<StoredCredential> {
  const [metadataKey, secretKey] = await Promise.all([deriveMetadataKey(), deriveSecretKey()]);

  const [metadataPayload, secretPayload] = await Promise.all([
    openEnvelope<MetadataPayload>(metadataKey, record.metadata),
    openEnvelope<SecretPayload>(secretKey, record.secret),
  ]);

  return {
    uniqueId: record.uniqueId,
    isSynced: record.isSynced ?? false,
    ...metadataPayload,
    ...secretPayload,
  };
}

// Settings Management
export async function saveSettings(settings: RenterdSettings): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(SETTINGS_STORE, 'readwrite')
      .objectStore(SETTINGS_STORE)
      .put({ ...settings, id: 'renterdSettings' }).onsuccess = () => resolve();
  });
}

export async function getSettings(): Promise<RenterdSettings | null> {
  const db = await openDB();
  return new Promise<RenterdSettings | null>((resolve) => {
    db
      .transaction(SETTINGS_STORE, 'readonly')
      .objectStore(SETTINGS_STORE)
      .get('renterdSettings').onsuccess = (event) =>
        resolve((event.target as IDBRequest<RenterdSettings>).result ?? null);
  });
}

// Stored Credential Management
export async function saveCredential(credential: StoredCredential): Promise<void> {
  const enc = await encryptCredential(credential);
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(enc).onsuccess = () => resolve();
  });
}

export async function getAllStoredCredentials(): Promise<StoredCredential[]> {
  const db = await openDB();
  const encryptedRecords: EncryptedRecord[] = await new Promise((resolve) => {
    db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .getAll().onsuccess = (event) =>
        resolve((event.target as IDBRequest<EncryptedRecord[]>).result ?? []);
  });

  const credentials: StoredCredential[] = [];
  for (const encryptedRecord of encryptedRecords) {
    try {
      credentials.push(await decryptCredential(encryptedRecord));
    } catch (error) {
      logError('[Store] decrypt error', error);
    }
  }
  return credentials;
}

export async function getAllCredentialsMetadata(): Promise<CredentialMetadata[]> {
  const db = await openDB();
  const encryptedRecords: EncryptedRecord[] = await new Promise((resolve) => {
    db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .getAll().onsuccess = (event) =>
        resolve((event.target as IDBRequest<EncryptedRecord[]>).result ?? []);
  });

  if (encryptedRecords.length === 0) return [];

  const metadataKey = await deriveMetadataKey();
  const metadataList: CredentialMetadata[] = [];
  for (const record of encryptedRecords) {
    try {
      const metadataPayload = await openEnvelope<MetadataPayload>(metadataKey, record.metadata);
      metadataList.push({
        uniqueId: record.uniqueId,
        rpId: metadataPayload.rpId,
        userName: metadataPayload.userName,
        creationTime: metadataPayload.creationTime,
        isSynced: record.isSynced ?? false,
      });
    } catch (error) {
      logError('[Store] decrypt metadata error', error);
    }
  }
  return metadataList;
}

async function getStoredCredentialByCredentialId(
  credentialId: string,
): Promise<StoredCredential | undefined> {
  return (await getAllStoredCredentials()).find((credential) => credential.credentialId === credentialId);
}

// Get encrypted credential directly from DB
export async function getEncryptedRecord(
  uniqueId: string,
): Promise<EncryptedRecord | null> {
  const db = await openDB();
  return new Promise((resolve) => {
    db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .get(uniqueId).onsuccess = (event) =>
        resolve((event.target as IDBRequest<EncryptedRecord>).result ?? null);
  });
}

// Save encrypted credential directly to DB
export async function saveEncryptedRecord(record: EncryptedRecord): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(record).onsuccess = () => resolve();
  });
}

// counter + Sia sync
export function updateCredentialCounter(credentialId: string): Promise<void> {
  const pendingLock = counterLocks.get(credentialId) ?? Promise.resolve();

  const lockPromise = pendingLock.then(async () => {
    const credential = await getStoredCredentialByCredentialId(credentialId);
    if (!credential) throw new Error('Credential not found');

    credential.counter++;
    credential.isSynced = false;

    const encUnsynced = await encryptCredential(credential);
    await saveEncryptedRecord(encUnsynced);

    uploadPasskeyDirect(encUnsynced).then(async (result) => {
      if (result.success) {
        encUnsynced.isSynced = true;
        await saveEncryptedRecord(encUnsynced);
      } else {
        logWarn('[Store] counter sync Sia', result.error);
      }
    }).catch((error) => {
      logError('[Store] Error in async upload', error);
    });
  });

  counterLocks.set(credentialId, lockPromise);
  void lockPromise.finally(() => counterLocks.delete(credentialId));
  return lockPromise;
}

// Utility Functions
export async function createUniqueId(rpId: string, credentialId: string): Promise<string> {
  const hashInput = new TextEncoder().encode(`${rpId}:${credentialId}`);
  const hash = await subtle.digest('SHA-256', hashInput);
  return base64UrlEncode(new Uint8Array(hash));
}

export async function savePrivateKey(
  credentialId: Uint8Array,
  rpId: string,
  privateKey: CryptoKey,
  userId: Uint8Array,
  publicKeyAlgorithm: number,
  userName?: string,
): Promise<void> {
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);

  const uniqueId = await createUniqueId(rpId, base64UrlEncode(credentialId));

  const stored: StoredCredential = {
    uniqueId,
    credentialId: base64UrlEncode(credentialId),
    rpId,
    privateKey: base64UrlEncode(new Uint8Array(pkcs8)),
    userHandle: base64UrlEncode(userId),
    publicKeyAlgorithm,
    counter: 0,
    userName,
    creationTime: Date.now(),
    isSynced: false,
  };

  await saveCredential(stored);
}

export async function loadPrivateKey(
  credentialId: string,
): Promise<[CryptoKey, SigningAlgorithm, number]> {
  const credential = await getStoredCredentialByCredentialId(credentialId);
  if (!credential) throw new Error('Credential not found');

  const pkcs8 = new Uint8Array(base64UrlDecode(credential.privateKey));

  let algorithmParams: EcKeyImportParams | RsaHashedImportParams | Algorithm;
  let signingAlgorithm: SigningAlgorithm;

  switch (credential.publicKeyAlgorithm) {
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
  return [privateKey, signingAlgorithm, credential.counter];
}

// Messaging in Background Context
export async function handleMessageInBackground(message: BackgroundMessage): Promise<unknown> {
  try {
    switch (message.type) {
      case 'saveCredential':
        if (!message.credential) return { error: 'Missing credential' };
        await saveCredential(message.credential as StoredCredential);
        return { status: 'ok' };

      case 'getStoredCredential':
        if (typeof message.credentialId !== 'string') return { error: 'Invalid credentialId' };
        return (
          (await getStoredCredentialByCredentialId(message.credentialId)) ?? { error: 'Not found' }
        );

      case 'getAllStoredCredentials':
        return getAllStoredCredentials();

      case 'findCredential': {
        const list = await getAllStoredCredentials();
        const opts = message.options;

        if (!opts || typeof opts !== 'object' || !('publicKey' in opts) || !opts.publicKey) {
          return { error: 'Invalid options: publicKey is required' };
        }

        const rp = extractRpId(opts);
        if (!rp) return { error: 'Missing rpId' };

        if (message.selectedCredentialId) {
          const found = list.find(
            (credential) => credential.credentialId === message.selectedCredentialId && credential.rpId === rp,
          );
          return found ?? { error: 'Not found' };
        }

        const allowCredentials = (opts.publicKey as { allowCredentials?: SerializedCredentialDescriptor[] })
          ?.allowCredentials;

        if (Array.isArray(allowCredentials) && allowCredentials.length) {
          for (const ac of allowCredentials) {
            const id = normalizeCredentialId(ac.id);
            if (!id) continue;
            const found = list.find((credential) => credential.credentialId === id && credential.rpId === rp);
            if (found) return found;
          }
        }
        return list.find((credential) => credential.rpId === rp) ?? { error: 'Not found' };
      }

      case 'updateCredentialCounter':
        if (typeof message.credentialId !== 'string') return { error: 'Invalid credentialId' };
        await updateCredentialCounter(message.credentialId);
        return { status: 'ok' };

      default:
        throw new Error(`Unknown message type: ${message.type}`);
    }
  } catch (error: unknown) {
    logError('[Store] background handler error', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { error: errorMessage };
  }
}

// Background proxy helpers
export async function findCredential(
  options: SerializedRequestOptions | GetAssertionOptions,
  selectedCredentialId?: string,
): Promise<StoredCredential> {
  const response = await handleMessageInBackground({
    type: 'findCredential',
    options,
    selectedCredentialId,
  }) as StoredCredential | { error: string };
  if ('error' in response) throw new Error(response.error);
  return response;
}

