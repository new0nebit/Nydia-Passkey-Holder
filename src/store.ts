import { Ed25519, ES256, RS256, SigningAlgorithm } from './algorithms';
import { logDebug, logError } from './logger';
import { uploadPasskeyDirect } from './sia';
import {
  BackgroundMessage,
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
    request.onerror = () => reject(request.error);
  });
}

// masterKey
let masterKey: CryptoKey | null = null;

async function loadMasterKeyFromDB(): Promise<CryptoKey | null> {
  if (masterKey) return masterKey;

  const db = await openDB();
  const item = await new Promise<{ key?: CryptoKey } | undefined>((resolve) => {
    db
      .transaction(SETTINGS_STORE, 'readonly')
      .objectStore(SETTINGS_STORE)
      .get('ephemeralKey').onsuccess = (event) =>
        resolve((event.target as IDBRequest<{ key?: CryptoKey }>).result);
  });

  if (item?.key) {
    masterKey = item.key;
    logDebug('[Store] masterKey loaded');
  }
  return masterKey;
}

async function getMasterKey(): Promise<CryptoKey> {
  const key = await loadMasterKeyFromDB();
  if (key) return key;
  throw new Error('masterKeyMissing');
}

export async function getMasterKeyIfAvailable(): Promise<CryptoKey | null> {
  return loadMasterKeyFromDB();
}

// Background-only: stores masterKey in IndexedDB
export async function setMasterKey(key: CryptoKey): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(SETTINGS_STORE, 'readwrite')
      .objectStore(SETTINGS_STORE)
      .put({ id: 'ephemeralKey', key }).onsuccess = () => resolve();
  });
  masterKey = key;
  logDebug('[Store] masterKey persisted');
}

// encrypt / decrypt helpers
async function encryptCredential(credential: StoredCredential): Promise<EncryptedRecord> {
  // Remove isSynced before encryption to avoid storing it inside data
  const { isSynced, ...withoutSync } = credential;

  const key = await getMasterKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(withoutSync)),
  );

  const record: EncryptedRecord = {
    uniqueId: credential.uniqueId,
    iv: base64UrlEncode(iv),
    data: base64UrlEncode(new Uint8Array(ciphertext)),
    isSynced: isSynced,
  };
  return record;
}

async function decryptCredential(record: EncryptedRecord): Promise<StoredCredential> {
  const key = await getMasterKey();
  const iv = new Uint8Array(base64UrlDecode(record.iv));
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    new Uint8Array(base64UrlDecode(record.data)),
  );
  const storedCredential: StoredCredential = JSON.parse(new TextDecoder().decode(plaintext));
  storedCredential.isSynced = record.isSynced ?? false;
  return storedCredential;
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
export async function saveStoredCredential(credential: StoredCredential): Promise<void> {
  const enc = await encryptCredential(credential);
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(enc).onsuccess = () => resolve();
  });
}

export async function getAllStoredCredentialsFromDB(): Promise<StoredCredential[]> {
  const db = await openDB();
  const encList: EncryptedRecord[] = await new Promise((resolve) => {
    db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .getAll().onsuccess = (event) =>
        resolve((event.target as IDBRequest<EncryptedRecord[]>).result ?? []);
  });

  const out: StoredCredential[] = [];
  for (const encryptedRecord of encList) {
    try {
      out.push(await decryptCredential(encryptedRecord));
    } catch (error) {
      logError('[Store] decrypt error', error);
    }
  }
  return out;
}

async function getCredentialById(
  credentialId: string,
): Promise<StoredCredential | undefined> {
  return (await getAllStoredCredentialsFromDB()).find((credential) => credential.credentialId === credentialId);
}

// Get encrypted credential directly from DB
export async function getEncryptedCredentialByUniqueId(
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
export async function saveEncryptedCredential(record: EncryptedRecord): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(record).onsuccess = () => resolve();
  });
}

// counter + Sia sync
export async function updateCredentialCounter(credentialId: string): Promise<void> {
  const prev = counterLocks.get(credentialId) ?? Promise.resolve();

  const next = prev.then(async () => {
    const credential = await getCredentialById(credentialId);
    if (!credential) throw new Error('Credential not found');

    credential.counter++;
    credential.isSynced = false;

    const encUnsynced = await encryptCredential(credential);
    await saveEncryptedCredential(encUnsynced);

    uploadPasskeyDirect(encUnsynced).then(async (result) => {
      if (result.success) {
        encUnsynced.isSynced = true;
        await saveEncryptedCredential(encUnsynced);
      } else {
        logError('[Store] counter sync Sia', result.error);
      }
    }).catch((error) => {
      logError('[Store] Error in async upload', error);
    });
  });

  counterLocks.set(credentialId, next);  
  next.finally(() => counterLocks.delete(credentialId));
}

// Utility Functions
export async function createUniqueId(rpId: string, credentialId: string): Promise<string> {
  const data = new TextEncoder().encode(`${rpId}:${credentialId}`);
  const hash = await subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

export async function savePrivateKey(
  credentialId: Uint8Array,
  rpId: string,
  privateKey: CryptoKey,
  userId: Uint8Array,
  cosePublicKey: Uint8Array,
  publicKeyAlgorithm: number,
  userIdHash: string,
  userName?: string,
): Promise<void> {
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
  const key = await getMasterKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedPkcs8 = await subtle.encrypt({ name: 'AES-GCM', iv }, key, pkcs8);

  const stored: StoredCredential = {
    uniqueId: await createUniqueId(rpId, base64UrlEncode(credentialId)),
    credentialId: base64UrlEncode(credentialId),
    rpId,
    userIdHash,
    privateKey: base64UrlEncode(new Uint8Array(encryptedPkcs8)),
    iv: base64UrlEncode(iv),
    userHandle: base64UrlEncode(userId),
    publicKey: base64UrlEncode(cosePublicKey),
    publicKeyAlgorithm,
    counter: 0,
    userName,
    creationTime: Date.now(),
    isSynced: false,
  };

  await saveStoredCredential(stored);
}

export async function loadPrivateKey(
  credentialId: string,
): Promise<[CryptoKey, SigningAlgorithm, number]> {
  const credential = await getCredentialById(credentialId);
  if (!credential) throw new Error('Credential not found');

  const key = await getMasterKey();
  const pkcs8 = await subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64UrlDecode(credential.iv)) },
    key,
    new Uint8Array(base64UrlDecode(credential.privateKey)),
  );

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
      case 'saveStoredCredential':
        if (!message.storedCredential) return { error: 'Missing storedCredential' };
        await saveStoredCredential(message.storedCredential as StoredCredential);
        return { status: 'ok' };

      case 'getStoredCredential':
        if (typeof message.credentialId !== 'string') return { error: 'Invalid credentialId' };
        return (
          (await getCredentialById(message.credentialId)) ?? { error: 'Not found' }
        );

      case 'getAllStoredCredentials':
        return getAllStoredCredentialsFromDB();

      case 'findCredential': {
        const list = await getAllStoredCredentialsFromDB();
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
  } catch (e: unknown) {
    logError('[Store] background handler error', e);
    const errorMessage = e instanceof Error ? e.message : String(e);
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

export async function getAllStoredCredentials(): Promise<StoredCredential[]> {
  const response = await handleMessageInBackground({
    type: 'getAllStoredCredentials',
  }) as StoredCredential[] | { error: string };
  if (!Array.isArray(response)) {
    if ('error' in response) throw new Error(response.error);
    return [];
  }
  return response;
}
