import { isSiteIcon } from './image';

// Separate from passkeys and Sia backups
const DB_NAME = 'NydiaSiteIcons';

async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore('preferences');
      request.result.createObjectStore('icons');
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

export async function readIcon(rpId: string): Promise<string | null> {
  const dataUrl = await access<unknown>('icons', 'readonly', (store) => store.get(rpId));
  return isSiteIcon(dataUrl) ? dataUrl : null;
}

export async function writeIcon(rpId: string, dataUrl: string): Promise<boolean> {
  await access('icons', 'readwrite', (store) => store.put(dataUrl, rpId));
  return true;
}
