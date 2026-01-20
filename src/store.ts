import browser from 'browser-api';

import { Ed25519, ES256, RS256, SigningAlgorithm } from './algorithms';
import { logError } from './logger';
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

// Check background context
export function isBackgroundContext(): boolean {
  const globalObj = globalThis as {
    ServiceWorkerGlobalScope?: new () => unknown;
  };

  const isServiceWorkerScope =
    typeof globalObj.ServiceWorkerGlobalScope === 'function' &&
    self instanceof globalObj.ServiceWorkerGlobalScope;

  if (isServiceWorkerScope) return true;

  if (typeof window !== 'undefined' && typeof browser !== 'undefined') {
    const bgUrls = [browser.runtime.getURL('_generated_background_page.html')];
    if (bgUrls.includes(window.location.href)) {
      return true;
    }
  }

  return false;
}

async function sendMessageToExtension<T = unknown>(msg: BackgroundMessage): Promise<T> {
  return isBackgroundContext()
    ? ((handleMessageInBackground(msg) as unknown) as Promise<T>)
    : (browser.runtime.sendMessage(msg) as Promise<T>);
}

type FindCredentialOptions = SerializedRequestOptions | GetAssertionOptions;

// Helper function to extract rpId from various option formats
function extractRpId(options: FindCredentialOptions): string | undefined {
  if (!options || typeof options !== 'object') return undefined;

  const opts = options as { publicKey?: unknown; origin?: string };
  if (!opts.publicKey || typeof opts.publicKey !== 'object') {
    // Fallback to origin
    return opts.origin ? new URL(opts.origin).hostname : undefined;
  }

  const pk = opts.publicKey as { rpId?: string; rp?: { id?: string } };
  return pk.rpId ?? pk.rp?.id ?? (opts.origin ? new URL(opts.origin).hostname : undefined);
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

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => setupStores(req.result);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// masterKey
let masterKey: CryptoKey | null = null;

async function getMasterKey(): Promise<CryptoKey> {
  if (masterKey) return masterKey;

  const db = await openDatabase();
  const item = await new Promise<{ key?: CryptoKey } | undefined>((res) => {
    db
      .transaction(SETTINGS_STORE, 'readonly')
      .objectStore(SETTINGS_STORE)
      .get('ephemeralKey').onsuccess = (e) =>
        res((e.target as IDBRequest<{ key?: CryptoKey }>).result);
  });

  if (item?.key) {
    masterKey = item.key;
    return masterKey;
  }
  throw new Error('masterKeyMissing');
}

// encrypt / decrypt helpers
async function encryptCredential(c: StoredCredential): Promise<EncryptedRecord> {
  // Remove isSynced before encryption to avoid storing it inside data
  const { isSynced, ...withoutSync } = c;

  const key = await getMasterKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(withoutSync)),
  );

  const record: EncryptedRecord = {
    uniqueId: c.uniqueId,
    iv: base64UrlEncode(iv),
    data: base64UrlEncode(new Uint8Array(ct)),
    isSynced: isSynced,
  };
  return record;
}

async function decryptCredential(r: EncryptedRecord): Promise<StoredCredential> {
  const key = await getMasterKey();
  const iv = new Uint8Array(base64UrlDecode(r.iv));
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    new Uint8Array(base64UrlDecode(r.data)),
  );
  const sc: StoredCredential = JSON.parse(new TextDecoder().decode(pt));
  sc.isSynced = r.isSynced ?? false;
  return sc;
}

// Settings Management
export async function saveSettings(settings: RenterdSettings): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((res) => {
    db
      .transaction(SETTINGS_STORE, 'readwrite')
      .objectStore(SETTINGS_STORE)
      .put({ ...settings, id: 'renterdSettings' }).onsuccess = () => res();
  });
}

export async function getSettings(): Promise<RenterdSettings | null> {
  const db = await openDatabase();
  return new Promise<RenterdSettings | null>((res) => {
    db
      .transaction(SETTINGS_STORE, 'readonly')
      .objectStore(SETTINGS_STORE)
      .get('renterdSettings').onsuccess = (e) =>
        res((e.target as IDBRequest<RenterdSettings>).result ?? null);
  });
}

// Stored Credential Management
export async function saveStoredCredential(c: StoredCredential): Promise<void> {
  const enc = await encryptCredential(c);
  const db = await openDatabase();
  await new Promise<void>((res) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(enc).onsuccess = () => res();
  });
}

export async function getAllStoredCredentialsFromDB(): Promise<StoredCredential[]> {
  const db = await openDatabase();
  const encList: EncryptedRecord[] = await new Promise((res) => {
    db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .getAll().onsuccess = (e) =>
        res((e.target as IDBRequest<EncryptedRecord[]>).result ?? []);
  });

  const out: StoredCredential[] = [];
  for (const r of encList) {
    try {
      out.push(await decryptCredential(r));
    } catch (e) {
      logError('decrypt error', e);
    }
  }
  return out;
}

async function getStoredCredentialByCredentialId(
  credentialId: string,
): Promise<StoredCredential | undefined> {
  return (await getAllStoredCredentialsFromDB()).find((c) => c.credentialId === credentialId);
}

// Get encrypted credential directly from DB
export async function getEncryptedCredentialByUniqueId(
  uniqueId: string,
): Promise<EncryptedRecord | null> {
  const db = await openDatabase();
  return new Promise((res) => {
    db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .get(uniqueId).onsuccess = (e) =>
        res((e.target as IDBRequest<EncryptedRecord>).result ?? null);
  });
}

// Save encrypted credential directly to DB
export async function saveEncryptedCredential(record: EncryptedRecord): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((res) => {
    db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(record).onsuccess = () => res();
  });
}

// counter + Sia sync
export async function updateCredentialCounter(credentialId: string): Promise<void> {
  const prev = counterLocks.get(credentialId) ?? Promise.resolve();

  const next = prev.then(async () => {
    const rec = await getStoredCredentialByCredentialId(credentialId);
    if (!rec) throw new Error('Credential not found');

    rec.counter++;
    rec.isSynced = false;

    const encUnsynced = await encryptCredential(rec);
    await saveEncryptedCredential(encUnsynced);

    uploadPasskeyDirect(encUnsynced).then(async (res) => {
      if (res.success) {
        encUnsynced.isSynced = true;
        await saveEncryptedCredential(encUnsynced);
      } else {
        logError('counter sync Sia', res.error);
      }
    }).catch((err) => {
      logError('Error in async upload', err);
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
  const rec = await getStoredCredentialByCredentialId(credentialId);
  if (!rec) throw new Error('Credential not found');

  const key = await getMasterKey();
  const pkcs8 = await subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64UrlDecode(rec.iv)) },
    key,
    new Uint8Array(base64UrlDecode(rec.privateKey)),
  );

  let params: EcKeyImportParams | RsaHashedImportParams | Algorithm;
  let algObj: SigningAlgorithm;

  switch (rec.publicKeyAlgorithm) {
    case -7:
      params = { name: 'ECDSA', namedCurve: 'P-256' };
      algObj = new ES256();
      break;
    case -257:
      params = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      algObj = new RS256();
      break;
    case -8:
      params = { name: 'Ed25519' };
      algObj = new Ed25519();
      break;
    default:
      throw new Error('Unsupported algorithm');
  }

  const privKey = await subtle.importKey('pkcs8', pkcs8, params, false, ['sign']);
  return [privKey, algObj, rec.counter];
}

// Messaging in Background Context
export async function handleMessageInBackground(message: BackgroundMessage): Promise<unknown> {
  try {
    switch (message.type) {
      case 'saveStoredCredential':
        if (!message.storedCredential) return { error: 'missing storedCredential' };
        await saveStoredCredential(message.storedCredential as StoredCredential);
        return { status: 'ok' };

      case 'getStoredCredential':
        if (typeof message.credentialId !== 'string') return { error: 'invalid credentialId' };
        return (
          (await getStoredCredentialByCredentialId(message.credentialId)) ?? { error: 'not found' }
        );

      case 'getAllStoredCredentials':
        return getAllStoredCredentialsFromDB();

      case 'findCredential': {
        const list = await getAllStoredCredentialsFromDB();
        const opts = message.options;

        if (!opts || typeof opts !== 'object' || !('publicKey' in opts) || !opts.publicKey) {
          return { error: 'Invalid options' };
        }

        const rp = extractRpId(opts);
        if (!rp) return { error: 'Missing rpId' };

        if (message.selectedCredentialId) {
          const found = list.find(
            (c) => c.credentialId === message.selectedCredentialId && c.rpId === rp,
          );
          return found ?? { error: 'not found' };
        }

        const allowCredentials = (opts.publicKey as { allowCredentials?: SerializedCredentialDescriptor[] })
          ?.allowCredentials;

        if (Array.isArray(allowCredentials) && allowCredentials.length) {
          for (const ac of allowCredentials) {
            const id = normalizeCredentialId(ac.id);
            if (!id) continue;
            const found = list.find((c) => c.credentialId === id && c.rpId === rp);
            if (found) return found;
          }
        }
        return list.find((c) => c.rpId === rp) ?? { error: 'not found' };
      }

      case 'updateCredentialCounter':
        if (typeof message.credentialId !== 'string') return { error: 'invalid credentialId' };
        await updateCredentialCounter(message.credentialId);
        return { status: 'ok' };

      default:
        throw new Error(`Unknown message type: ${message.type}`);
    }
  } catch (e: unknown) {
    logError('[store] background handler error', e);
    const message = e instanceof Error ? e.message : String(e);
    return { error: message };
  }
}

// Foreground Proxies
export async function findCredential(
  options: SerializedRequestOptions | GetAssertionOptions,
  selectedCredentialId?: string,
): Promise<StoredCredential> {
  const r = await sendMessageToExtension<StoredCredential | { error: string }>({
    type: 'findCredential',
    options,
    selectedCredentialId,
  });
  if ('error' in r) throw new Error(r.error);
  return r;
}

export async function getAllStoredCredentials(): Promise<StoredCredential[]> {
  const r = await sendMessageToExtension<StoredCredential[] | { error: string }>({
    type: 'getAllStoredCredentials',
  });
  if (!Array.isArray(r)) {
    if ('error' in r) throw new Error(r.error);
    return [];
  }
  return r;
}
