import { getRootKeyIfAvailable } from '../store';
import { base64UrlEncode } from '../utils/base64url';
import { isSiteIcon } from './image';

// Separate from passkeys and Sia backups
const DB_NAME = 'NydiaSiteIcons';
const encoder = new TextEncoder();

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

async function access<T>(
  store: string,
  mode: IDBTransactionMode,
  operation: (value: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(store, mode);
    const request = operation(transaction.objectStore(store));
    transaction.oncomplete = () => {
      db.close();
      resolve(request.result);
    };
    transaction.onabort = () => {
      db.close();
      reject(transaction.error ?? new Error('Icon storage transaction failed'));
    };
  });
}

export async function iconsEnabled(): Promise<boolean> {
  return (await access<unknown>('preferences', 'readonly', (store) => store.get('enabled'))) === true;
}

export async function setIconsEnabled(enabled: boolean): Promise<void> {
  await access('preferences', 'readwrite', (store) => store.put(enabled, 'enabled'));
}

async function cacheKeys(rpId: string): Promise<{ id: string; key: CryptoKey } | null> {
  const root = await getRootKeyIfAvailable();
  if (!root) return null;
  const params = (purpose: string): HkdfParams => ({
    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode(purpose),
  });
  const [indexKey, key] = await Promise.all([
    crypto.subtle.deriveKey(params('site-icons:index:v1'), root,
      { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']),
    crypto.subtle.deriveKey(params('site-icons:data:v1'), root,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
  ]);
  const id = base64UrlEncode(await crypto.subtle.sign('HMAC', indexKey, encoder.encode(rpId)));
  return { id, key };
}

export async function readIcon(rpId: string): Promise<string | null> {
  const keys = await cacheKeys(rpId);
  if (!keys) return null;
  const record = await access<unknown>('icons', 'readonly', (store) => store.get(keys.id));
  if (
    !record || typeof record !== 'object' ||
    !('iv' in record) || !(record.iv instanceof Uint8Array) ||
    !('data' in record) || !(record.data instanceof ArrayBuffer)
  ) return null;
  try {
    const plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: new Uint8Array(record.iv), additionalData: encoder.encode(keys.id),
    }, keys.key, record.data);
    const dataUrl = new TextDecoder().decode(plaintext);
    return isSiteIcon(dataUrl) ? dataUrl : null;
  } catch {
    // Wrong key or corrupt entry: a miss
    return null;
  }
}

export async function writeIcon(rpId: string, dataUrl: string): Promise<boolean> {
  const keys = await cacheKeys(rpId);
  if (!keys) return false;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({
    name: 'AES-GCM', iv, additionalData: encoder.encode(keys.id),
  }, keys.key, encoder.encode(dataUrl));
  await access('icons', 'readwrite', (store) => store.put({ iv, data }, keys.id));
  return true;
}
