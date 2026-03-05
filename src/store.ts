import { logDebug, logError, logWarn } from './logger';
import { uploadPasskeyDirect } from './sia';
import {
  BackgroundMessage,
  CredentialMetadata,
  EncryptedEnvelope,
  EncryptedRecord,
  RenterdSettings,
  StoredCredential,
} from './types';
import { base64UrlDecode, base64UrlEncode } from './utils/base64url';

// Web Crypto API
const subtle = crypto.subtle;

// Simple per-credential mutex to avoid race conditions during counter updates
const counterLocks: Map<string, Promise<void>> = new Map();

// IndexedDB
const DB_NAME = 'NydiaDB';
const DB_VERSION = 4;
const STORE_NAME = 'storedCredentials';
const SETTINGS_STORE = 'settings';

function setupStores(db: IDBDatabase) {
  if (!db.objectStoreNames.contains(STORE_NAME)) {
    db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
  }
  if (!db.objectStoreNames.contains(SETTINGS_STORE)) {
    db.createObjectStore(SETTINGS_STORE, { keyPath: 'id' });
  }
}

function openDB(): Promise<IDBDatabase> {
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
export type SecretPayload = {
  credentialId: string;
  userHandle: string;
  publicKeyAlgorithm: number;
  privateKey: string;
  counter: number;
};

export async function openSecret(uniqueId: string): Promise<SecretPayload> {
  const record = await getEncryptedRecord(uniqueId);
  if (!record) throw new Error('Credential not found');
  const key = await deriveSecretKey();
  return openEnvelope<SecretPayload>(key, record.secret);
}

// Settings Management
async function saveSettings(settings: RenterdSettings): Promise<void> {
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
async function saveCredential(credential: StoredCredential): Promise<void> {
  const encryptedRecord = await encryptCredential(credential);
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(encryptedRecord).onsuccess = () => resolve();
  });
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
export function updateCredentialCounter(uniqueId: string): Promise<void> {
  const pendingLock = counterLocks.get(uniqueId) ?? Promise.resolve();

  const lockPromise = pendingLock.then(async () => {
    const record = await getEncryptedRecord(uniqueId);
    if (!record) throw new Error('Credential not found');

    const secretKey = await deriveSecretKey();
    const secretPayload = await openEnvelope<SecretPayload>(secretKey, record.secret);
    secretPayload.counter++;

    const { credentialId, userHandle, publicKeyAlgorithm, privateKey, counter } = secretPayload;
    const newSecret = await sealEnvelope(secretKey, { credentialId, userHandle, publicKeyAlgorithm, privateKey, counter });
    const updated: EncryptedRecord = { ...record, secret: newSecret, isSynced: false };
    await saveEncryptedRecord(updated);

    uploadPasskeyDirect(updated).then(async (result) => {
      if (result.success) {
        updated.isSynced = true;
        await saveEncryptedRecord(updated);
      } else {
        logWarn('[Store] counter sync Sia', result.error);
      }
    }).catch((error) => {
      logError('[Store] Error in async upload', error);
    });
  });

  counterLocks.set(uniqueId, lockPromise);
  void lockPromise.finally(() => counterLocks.delete(uniqueId));
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

// Messaging in Background Context
export async function handleMessageInBackground(message: BackgroundMessage): Promise<unknown> {
  try {
    switch (message.type) {
      case 'updateCredentialCounter':
        if (typeof message.uniqueId !== 'string') return { error: 'Invalid uniqueId' };
        await updateCredentialCounter(message.uniqueId);
        return { status: 'ok' };

      case 'getAllCredentialsMetadata':
        return getAllCredentialsMetadata();

      case 'getSettings':
        return getSettings();

      case 'saveSettings':
        if (!message.settings) return { error: 'Missing settings' };
        await saveSettings(message.settings as RenterdSettings);
        return { status: 'ok' };

      case 'deleteCredential': {
        if (typeof message.uniqueId !== 'string') return { error: 'Invalid uniqueId' };
        const db = await openDB();
        await new Promise<void>((resolve, reject) => {
          const transaction = db.transaction(STORE_NAME, 'readwrite');
          transaction.objectStore(STORE_NAME).delete(message.uniqueId!);
          transaction.oncomplete = () => resolve();
          transaction.onerror = () => reject(transaction.error ?? new Error('Failed to delete credential'));
        });
        return { status: 'ok' };
      }

      default:
        throw new Error(`Unknown message type: ${message.type}`);
    }
  } catch (error: unknown) {
    logError('[Store] background handler error', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { error: errorMessage };
  }
}
