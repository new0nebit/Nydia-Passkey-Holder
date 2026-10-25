import { logDebug, logError } from './logger';
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

// IndexedDB
const DB_NAME = 'NydiaDB';
const DB_VERSION = 4;
const PASSKEY_STORE = 'passkeys';
const SETTINGS_STORE = 'settings';

function setupStores(db: IDBDatabase) {
  if (!db.objectStoreNames.contains(PASSKEY_STORE)) {
    db.createObjectStore(PASSKEY_STORE, { keyPath: 'uniqueId' });
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
const HKDF_SETTINGS_INFO = new TextEncoder().encode('renterd-settings:v1');

async function loadRootKeyFromDB(): Promise<CryptoKey | null> {
  if (rootKey) return rootKey;

  const db = await openDB();
  const rootKeyEntry = await new Promise<{ key?: CryptoKey } | undefined>((resolve, reject) => {
    const transaction = db.transaction(SETTINGS_STORE, 'readonly');
    const request = transaction.objectStore(SETTINGS_STORE).get('rootKey') as IDBRequest<{ key?: CryptoKey } | undefined>;
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Failed to read encryption key'));
    transaction.oncomplete = () => db.close();
    transaction.onabort = () => {
      db.close();
      reject(transaction.error ?? new Error('Failed to read encryption key'));
    };
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
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(SETTINGS_STORE, 'readwrite');
    transaction.objectStore(SETTINGS_STORE).put({ id: 'rootKey', key });
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onabort = () => {
      db.close();
      reject(transaction.error ?? new Error('Failed to save encryption key'));
    };
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
};

export async function openSecret(uniqueId: string): Promise<SecretPayload> {
  const record = await getEncryptedRecord(uniqueId);
  if (!record) throw new Error('Credential not found');
  const secretKey = await deriveSecretKey();
  return openEnvelope<SecretPayload>(secretKey, record.secret);
}

// Settings Management
const SETTINGS_ID = 'renterdSettings';
type SettingsRecord = EncryptedEnvelope & { id: typeof SETTINGS_ID; version: 1 };

function isSettingsRecord(value: unknown): value is SettingsRecord {
  return !!value && typeof value === 'object' &&
    'id' in value && value.id === SETTINGS_ID &&
    'version' in value && value.version === 1 &&
    'iv' in value && typeof value.iv === 'string' &&
    'data' in value && typeof value.data === 'string';
}

function isSettings(value: unknown): value is RenterdSettings {
  return !!value && typeof value === 'object' &&
    'serverAddress' in value && typeof value.serverAddress === 'string' &&
    'serverPort' in value && typeof value.serverPort === 'number' &&
    Number.isInteger(value.serverPort) && value.serverPort > 0 && value.serverPort <= 65535 &&
    'password' in value && typeof value.password === 'string' &&
    'bucketName' in value && typeof value.bucketName === 'string' &&
    (!('serverProtocol' in value) || value.serverProtocol === undefined ||
      value.serverProtocol === 'http' || value.serverProtocol === 'https');
}

function isPlaintextSettings(value: unknown): value is RenterdSettings {
  return isSettings(value) && !('version' in value || 'iv' in value || 'data' in value);
}

// Do not persist extra fields received through messaging or an older record.
function settingsFields({ serverAddress, serverPort, password, bucketName, serverProtocol }: RenterdSettings) {
  return { serverAddress, serverPort, password, bucketName, ...(serverProtocol ? { serverProtocol } : {}) };
}

async function sealSettings(settings: RenterdSettings): Promise<SettingsRecord> {
  if (!isSettings(settings)) throw new Error('Invalid renterd settings');
  const key = await deriveAesKey(HKDF_SETTINGS_INFO);
  const envelope = await sealEnvelope(key, settingsFields(settings));
  return { id: SETTINGS_ID, version: 1, ...envelope };
}

async function openSettings(record: SettingsRecord): Promise<RenterdSettings> {
  const key = await deriveAesKey(HKDF_SETTINGS_INFO);
  try {
    if (base64UrlDecode(record.iv).length !== 12) throw new Error('Invalid IV');
    const settings = await openEnvelope<unknown>(key, record);
    if (!isSettings(settings)) throw new Error('Invalid settings payload');
    return settingsFields(settings);
  } catch {
    // Never treat damaged ciphertext or a wrong key as missing settings.
    throw new Error('Unable to decrypt renterd settings');
  }
}

async function readSettingsRecord(): Promise<unknown> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(SETTINGS_STORE, 'readonly');
    const request = transaction.objectStore(SETTINGS_STORE).get(SETTINGS_ID);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Failed to read renterd settings'));
    transaction.oncomplete = () => db.close();
    transaction.onabort = () => {
      db.close();
      reject(transaction.error ?? new Error('Failed to read renterd settings'));
    };
  });
}

function sameSettingsRecord(current: unknown, expected: SettingsRecord | RenterdSettings): boolean {
  if (isSettingsRecord(expected)) {
    return isSettingsRecord(current) && current.iv === expected.iv && current.data === expected.data;
  }
  return isPlaintextSettings(current) &&
    current.serverAddress === expected.serverAddress && current.serverPort === expected.serverPort &&
    current.password === expected.password && current.bucketName === expected.bucketName &&
    current.serverProtocol === expected.serverProtocol;
}

// Crypto runs before opening the transaction. The comparison and replacement
// run together, so migration and protocol detection cannot overwrite a save.
async function writeSettingsRecord(
  record: SettingsRecord,
  expected?: SettingsRecord | RenterdSettings,
): Promise<boolean> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(SETTINGS_STORE, 'readwrite');
    const store = transaction.objectStore(SETTINGS_STORE);
    let written = false;
    const put = () => { store.put(record); written = true; };
    if (expected) {
      const request = store.get(SETTINGS_ID);
      request.onsuccess = () => {
        if (sameSettingsRecord(request.result, expected)) put();
      };
    } else {
      put();
    }
    transaction.oncomplete = () => { db.close(); resolve(written); };
    transaction.onabort = () => {
      db.close();
      reject(transaction.error ?? new Error('Failed to save renterd settings'));
    };
  });
}

async function saveSettings(settings: RenterdSettings): Promise<void> {
  await writeSettingsRecord(await sealSettings(settings));
}

async function loadSettings(): Promise<{ settings: RenterdSettings; record: SettingsRecord } | null> {
  for (;;) {
    const record = await readSettingsRecord();
    if (record === undefined) return null;
    if (isSettingsRecord(record)) return { settings: await openSettings(record), record };
    if (!isPlaintextSettings(record)) throw new Error('Unsupported or damaged renterd settings format');

    const settings = settingsFields(record);
    const sealed = await sealSettings(settings);
    if (await writeSettingsRecord(sealed, record)) return { settings, record: sealed };
    // A concurrent write won. Read its settings instead of returning stale data.
  }
}

// Do not publish a protocol detected with settings that have since changed,
// nor replace one already saved: an older detection may finish later.
export async function saveServerProtocol(
  settings: RenterdSettings,
  serverProtocol: 'http' | 'https',
): Promise<void> {
  const current = await loadSettings();
  if (!current || current.settings.serverProtocol || current.settings.serverAddress !== settings.serverAddress ||
    current.settings.serverPort !== settings.serverPort || current.settings.password !== settings.password) return;
  const sealed = await sealSettings({ ...current.settings, serverProtocol });
  await writeSettingsRecord(sealed, current.record);
}

export async function getSettings(): Promise<RenterdSettings | null> {
  return (await loadSettings())?.settings ?? null;
}

// Migrate on startup too, without waiting for the user to open the menu.
export async function sealPlaintextSettings(): Promise<void> {
  const record = await readSettingsRecord();
  if (record !== undefined && !isSettingsRecord(record)) await loadSettings();
}

// Stored Credential Management
async function saveCredential(credential: StoredCredential): Promise<void> {
  const encryptedRecord = await encryptCredential(credential);
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(PASSKEY_STORE, 'readwrite')
      .objectStore(PASSKEY_STORE)
      .put(encryptedRecord).onsuccess = () => resolve();
  });
}

export async function getAllCredentialsMetadata(): Promise<CredentialMetadata[]> {
  const db = await openDB();
  const encryptedRecords: EncryptedRecord[] = await new Promise((resolve) => {
    db
      .transaction(PASSKEY_STORE, 'readonly')
      .objectStore(PASSKEY_STORE)
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

// Null unless every record decrypts
export async function getAllRpIds(): Promise<Set<string> | null> {
  if (!(await getRootKeyIfAvailable())) return null;

  const db = await openDB();
  const encryptedRecords = await new Promise<EncryptedRecord[]>((resolve, reject) => {
    const request = db
      .transaction(PASSKEY_STORE, 'readonly')
      .objectStore(PASSKEY_STORE)
      .getAll() as IDBRequest<EncryptedRecord[]>;
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Failed to read passkeys'));
  });

  const metadataKey = await deriveMetadataKey();
  const rpIds = new Set<string>();
  for (const record of encryptedRecords) {
    try {
      const { rpId } = await openEnvelope<MetadataPayload>(metadataKey, record.metadata);
      if (typeof rpId !== 'string') return null;
      rpIds.add(rpId);
    } catch {
      return null;
    }
  }
  return rpIds;
}

export async function getCredentialsMetadataByUniqueIds(
  uniqueIds: string[],
): Promise<CredentialMetadata[]> {
  if (uniqueIds.length === 0) return [];

  const metadataKey = await deriveMetadataKey();
  const metadataList: CredentialMetadata[] = [];

  for (const uniqueId of uniqueIds) {
    const record = await getEncryptedRecord(uniqueId);
    if (!record) continue;

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
      logError('[Store] decrypt metadata by uniqueIds error', error);
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
      .transaction(PASSKEY_STORE, 'readonly')
      .objectStore(PASSKEY_STORE)
      .get(uniqueId).onsuccess = (event) =>
        resolve((event.target as IDBRequest<EncryptedRecord>).result ?? null);
  });
}

// Save encrypted credential directly to DB
export async function saveEncryptedRecord(record: EncryptedRecord): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve) => {
    db
      .transaction(PASSKEY_STORE, 'readwrite')
      .objectStore(PASSKEY_STORE)
      .put(record).onsuccess = () => resolve();
  });
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
): Promise<string> {
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);

  const uniqueId = await createUniqueId(rpId, base64UrlEncode(credentialId));

  const stored: StoredCredential = {
    uniqueId,
    credentialId: base64UrlEncode(credentialId),
    rpId,
    privateKey: base64UrlEncode(new Uint8Array(pkcs8)),
    userHandle: base64UrlEncode(userId),
    publicKeyAlgorithm,
    userName,
    creationTime: Date.now(),
    isSynced: false,
  };

  await saveCredential(stored);
  return uniqueId;
}

// Messaging in Background Context
export async function handleMessageInBackground(message: BackgroundMessage): Promise<unknown> {
  try {
    switch (message.type) {
      case 'getAllCredentialsMetadata':
        return getAllCredentialsMetadata();

      case 'getSettings':
        return await getSettings();

      case 'saveSettings':
        if (!message.settings) return { error: 'Missing settings' };
        await saveSettings(message.settings as RenterdSettings);
        return { status: 'ok' };

      case 'deleteCredential': {
        if (typeof message.uniqueId !== 'string') return { error: 'Invalid uniqueId' };
        const db = await openDB();
        await new Promise<void>((resolve, reject) => {
          const transaction = db.transaction(PASSKEY_STORE, 'readwrite');
          transaction.objectStore(PASSKEY_STORE).delete(message.uniqueId!);
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
