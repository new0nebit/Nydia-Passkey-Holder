import { getAllRpIds, getRootKeyIfAvailable } from '../store';
import { base64UrlEncode } from '../utils/base64url';
import { isIconDataUrl } from './image';

// Separate from passkeys and Sia backups
const DB_NAME = 'NydiaSiteIcons';
// Misses are encrypted like icons
const MISSING = /^missing:(\d{1,15})$/;
const encoder = new TextEncoder();

type IconKeys = { id: string; key: CryptoKey };
type IconRecord = { iv: Uint8Array; data: ArrayBuffer };
type IconEntry = { dataUrl: string } | { missingSince: number };

async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onupgradeneeded = (event) => {
      if (event.oldVersion === 0) {
        request.result.createObjectStore('preferences');
        request.result.createObjectStore('icons');
      } else {
        // Drop plaintext icons, keep the preference
        request.transaction?.objectStore('icons').clear();
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Cannot open icon storage'));
  });
}

async function transact(
  stores: string[],
  mode: IDBTransactionMode,
  operation: (transaction: IDBTransaction) => void,
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(stores, mode);
    operation(transaction);
    transaction.oncomplete = () => {
      db.close();
      resolve();
    };
    transaction.onabort = () => {
      db.close();
      reject(transaction.error ?? new Error('Icon storage transaction failed'));
    };
  });
}

async function access<T>(
  store: string,
  mode: IDBTransactionMode,
  operation: (value: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  let request!: IDBRequest<T>;
  await transact([store], mode, (transaction) => { request = operation(transaction.objectStore(store)); });
  return request.result;
}

export async function iconsEnabled(): Promise<boolean> {
  return (await access<unknown>('preferences', 'readonly', (store) => store.get('enabled'))) === true;
}

export async function setIconsEnabled(enabled: boolean): Promise<void> {
  await transact(['preferences', 'icons'], 'readwrite', (transaction) => {
    transaction.objectStore('preferences').put(enabled, 'enabled');
    if (!enabled) transaction.objectStore('icons').clear();
  });
}

function params(purpose: string): HkdfParams {
  return { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode(purpose) };
}

function deriveIndexKey(root: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(params('site-icons:index:v1'), root,
    { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
}

async function recordId(indexKey: CryptoKey, rpId: string): Promise<string> {
  return base64UrlEncode(await crypto.subtle.sign('HMAC', indexKey, encoder.encode(rpId)));
}

async function cacheKeys(rpId: string): Promise<IconKeys | null> {
  const root = await getRootKeyIfAvailable();
  if (!root) return null;
  const [indexKey, key] = await Promise.all([
    deriveIndexKey(root),
    crypto.subtle.deriveKey(params('site-icons:data:v1'), root,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
  ]);
  return { id: await recordId(indexKey, rpId), key };
}

function isIconRecord(value: unknown): value is IconRecord {
  return !!value && typeof value === 'object' &&
    'iv' in value && value.iv instanceof Uint8Array &&
    'data' in value && value.data instanceof ArrayBuffer;
}

// A fresh IV per write marks the version
function version(record: unknown): string | null {
  return isIconRecord(record) ? base64UrlEncode(record.iv) : null;
}

async function seal(keys: IconKeys, plaintext: string): Promise<IconRecord> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({
    name: 'AES-GCM', iv, additionalData: encoder.encode(keys.id),
  }, keys.key, encoder.encode(plaintext));
  return { iv, data };
}

async function unseal(keys: IconKeys, record: unknown): Promise<IconEntry | null> {
  if (!isIconRecord(record)) return null;
  try {
    const plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: new Uint8Array(record.iv), additionalData: encoder.encode(keys.id),
    }, keys.key, record.data);
    const value = new TextDecoder().decode(plaintext);
    if (isIconDataUrl(value)) return { dataUrl: value };
    const missing = MISSING.exec(value);
    return missing ? { missingSince: Number(missing[1]) } : null;
  } catch {
    // Wrong key or corrupt entry: a miss
    return null;
  }
}

export async function readIcon(rpId: string): Promise<IconEntry | null> {
  const keys = await cacheKeys(rpId);
  if (!keys) return null;
  return unseal(keys, await access<unknown>('icons', 'readonly', (store) => store.get(keys.id)));
}

// Writes only while enabled, in one transaction
async function putWhileEnabled(id: string, record: IconRecord, expected?: { record: unknown }): Promise<boolean> {
  let written = false;
  await transact(['preferences', 'icons'], 'readwrite', (transaction) => {
    const icons = transaction.objectStore('icons');
    const enabled = transaction.objectStore('preferences').get('enabled');
    enabled.onsuccess = () => {
      if (enabled.result !== true) return;
      const current = icons.get(id);
      current.onsuccess = () => {
        if (expected && version(current.result) !== version(expected.record)) return;
        icons.put(record, id);
        written = true;
      };
    };
  });
  return written;
}

export async function writeIcon(rpId: string, dataUrl: string): Promise<boolean> {
  const keys = await cacheKeys(rpId);
  if (!keys) return false;
  return putWhileEnabled(keys.id, await seal(keys, dataUrl));
}

// Never overwrites an icon
export async function markIconMissing(rpId: string): Promise<boolean> {
  const keys = await cacheKeys(rpId);
  if (!keys) return false;
  const current = await access<unknown>('icons', 'readonly', (store) => store.get(keys.id));
  const entry = await unseal(keys, current);
  if (entry && 'dataUrl' in entry) return false;
  return putWhileEnabled(keys.id, await seal(keys, `missing:${Date.now()}`), { record: current });
}

// Keeps icons of stored passkeys only
export async function pruneIcons(): Promise<void> {
  const root = await getRootKeyIfAvailable();
  const rpIds = root ? await getAllRpIds() : null;
  if (!root || !rpIds) return;
  const indexKey = await deriveIndexKey(root);
  const keep = new Set(await Promise.all([...rpIds].map((rpId) => recordId(indexKey, rpId))));
  await transact(['icons'], 'readwrite', (transaction) => {
    const store = transaction.objectStore('icons');
    const request = store.getAllKeys();
    request.onsuccess = () => {
      for (const id of request.result) {
        if (typeof id !== 'string' || !keep.has(id)) store.delete(id);
      }
    };
  });
}
