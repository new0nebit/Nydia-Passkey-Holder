import browser from 'browser-api';

import { 
  createCredential,
  getAvailableCredentials,
  handleGetAssertion,
  initializeAuthenticator,
} from './authenticator';
import { base64UrlToArrayBuffer } from './base64url';
import { logError, logInfo } from './logger';
import { 
  downloadPasskeyFromRenterd,
  getPasskeysFromRenterd,
  uploadPasskeyDirect,
} from './sia';
import { 
  handleMessageInBackground,
  getSettings,
  saveEncryptedCredential,
  getEncryptedCredentialByUniqueId,
} from './store';
import { EncryptedRecord } from './types';

// IndexedDB
const DB_NAME = 'NydiaDB';
const DB_VER = 4;

function openDB(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('storedCredentials'))
        db.createObjectStore('storedCredentials', { keyPath: 'uniqueId' }).createIndex(
          'credentialId',
          'credentialId',
        );
      if (!db.objectStoreNames.contains('settings'))
        db.createObjectStore('settings', { keyPath: 'id' });
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

// masterKey and RSA wrapping key pair
let masterKey: CryptoKey | null = null;
let wrappingKeyPair: CryptoKeyPair | null = null;

async function loadMasterKey(): Promise<CryptoKey | null> {
  if (masterKey) return masterKey;

  const db = await openDB();
  const rec = await new Promise<{ key?: CryptoKey } | undefined>((r) => {
    db.transaction('settings', 'readonly').objectStore('settings').get('ephemeralKey').onsuccess = (
      e,
    ) => r((e.target as any).result);
  });

  if (rec?.key) {
    masterKey = rec.key;
    logInfo('masterKey loaded');
  }
  return masterKey;
}

async function persistKey(key: CryptoKey): Promise<void> {
  const db = await openDB();
  await new Promise<void>((r) => {
    db
      .transaction('settings', 'readwrite')
      .objectStore('settings')
      .put({ id: 'ephemeralKey', key }).onsuccess = () => r();
  });
  masterKey = key;
  logInfo('masterKey persisted');
}

// RSA key pair generation for secure key transfer
async function initializeWrappingKey(): Promise<CryptoKeyPair> {
  logInfo('Generating RSA-OAEP key pair for secure transfer');

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true, // extractable public key
    ['wrapKey', 'unwrapKey'],
  );

  logInfo('RSA-OAEP key pair generated');
  return keyPair;
}

// Clean up sensitive data
function secureCleanup(data: Uint8Array | number[] | null): void {
  if (!data) return;

  if (data instanceof Uint8Array) {
    crypto.getRandomValues(data);
    data.fill(0);
  } else if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i++) {
      data[i] = Math.floor(Math.random() * 256);
    }
    data.fill(0);
  }
}

// Firefox self-send patch
function patchSelfSend(local: (m: any) => Promise<any>) {
  const rt = browser.runtime;
  if (!rt?.sendMessage) return;

  const myId = rt.id;
  const orig = rt.sendMessage.bind(rt);

  rt.sendMessage = ((...args: any[]) => {
    let extId: string | undefined, msg: any;
    if (args.length === 1) msg = args[0];
    else [extId, msg] = args;

    return !extId || extId === myId ? local(msg) : orig(...(args as any));
  }) as typeof rt.sendMessage;

  logInfo('runtime.sendMessage patched');
}

// Deserializes the options object by converting base64url strings to ArrayBuffers.
function deserializeOptions(o: any): any {
  const out = { ...o };
  if (o.publicKey) {
    const cv = base64UrlToArrayBuffer;
    out.publicKey = { ...o.publicKey };

    if (typeof o.publicKey.challenge === 'string')
      out.publicKey.challenge = cv(o.publicKey.challenge);

    if (o.publicKey.user && typeof o.publicKey.user.id === 'string')
      out.publicKey.user = { ...o.publicKey.user, id: cv(o.publicKey.user.id) };

    const map = (arr?: any[]) => arr?.map((c: any) => ({ ...c, id: cv(c.id) }));
    out.publicKey.excludeCredentials = map(o.publicKey.excludeCredentials);
    out.publicKey.allowCredentials = map(o.publicKey.allowCredentials);
  }
  out.origin = o.origin;
  return out;
}

// Checks if the given object is a valid EncryptedRecord
function isValidEncryptedRecord(x: any): x is EncryptedRecord {
  return x && typeof x === 'object' && 'uniqueId' in x && 'iv' in x && 'data' in x;
}

// Handles the upload of a single passkey to renterd
async function handleUploadToSia(uniqueId: string) {
  // Get encrypted record directly from DB
  const encryptedRecord = await getEncryptedCredentialByUniqueId(uniqueId);
  if (!encryptedRecord) {
    return { success: false, error: 'Passkey not found' };
  }

  // Upload encrypted record as-is
  const result = await uploadPasskeyDirect(encryptedRecord);

  // If upload successful, update isSynced flag
  if (result.success) {
    encryptedRecord.isSynced = true;
    await saveEncryptedCredential(encryptedRecord);
  }

  return result;
}

// Handles uploading multiple unsynced passkeys to renterd
async function handleUploadUnsyncedPasskeys(uniqueIds: string[]) {
  let ok = 0,
    fl = 0;

  for (const uniqueId of uniqueIds) {
    try {
      const { success } = await handleUploadToSia(uniqueId);
      if (success) ok++;
      else fl++;
    } catch {
      fl++;
    }
  }

  return { success: fl === 0, uploadedCount: ok, failedCount: fl };
}

// Handles syncing passkeys from renterd to the extension
async function handleSyncFromSia() {
  const settings = await getSettings();
  if (!settings) return { success: false, error: 'no renterd settings' };

  const files = await getPasskeysFromRenterd(settings);
  let synced = 0,
    failed = 0;

  for (const f of files) {
    try {
      const encryptedRecord = await downloadPasskeyFromRenterd(f, settings);

      if (!isValidEncryptedRecord(encryptedRecord)) {
        failed++;
        continue;
      }

      // Save encrypted record directly to DB
      await saveEncryptedCredential(encryptedRecord);
      synced++;
    } catch {
      failed++;
    }
  }
  return { success: failed === 0, syncedCount: synced, failedCount: failed };
}

// Router
async function router(msg: any): Promise<any> {
  try {
    switch (msg.type) {
      case 'createCredential':
        if (!(await loadMasterKey())) return { error: 'masterKeyMissing' };
        return createCredential(deserializeOptions(msg.options));

      case 'handleGetAssertion':
        if (!(await loadMasterKey())) return { error: 'masterKeyMissing' };
        return handleGetAssertion(deserializeOptions(msg.options), msg.selectedCredentialId);

      case 'getAvailableCredentials':
        return getAvailableCredentials(msg.rpId);

      // Use uniqueId
      case 'uploadToSia':
        return handleUploadToSia(msg.uniqueId);

      case 'uploadUnsyncedPasskeys':
        return handleUploadUnsyncedPasskeys(msg.uniqueIds);

      case 'syncFromSia':
        return handleSyncFromSia();

      // Get public key for wrapping
      case 'getWrappingPublicKey': {
        try {
          // Lazy initialization - generate only when needed
          if (!wrappingKeyPair) {
            wrappingKeyPair = await initializeWrappingKey();
          }

          // Export public key in SPKI format
          const publicKeyBuffer = await crypto.subtle.exportKey('spki', wrappingKeyPair.publicKey);

          return {
            publicKey: Array.from(new Uint8Array(publicKeyBuffer)),
            algorithm: 'RSA-OAEP',
            hash: 'SHA-256',
          };
        } catch (e: any) {
          logError('Failed to export public key', e);
          return { error: 'Failed to generate wrapping key' };
        }
      }

      // Store wrapped key using RSA-OAEP
      case 'storeWrappedKey': {
        try {
          // Validate input
          if (!Array.isArray(msg.wrappedKey)) {
            return { error: 'Invalid wrapped key format' };
          }

          if (!wrappingKeyPair) {
            return { error: 'Wrapping key pair not initialized' };
          }

          // Convert array back to Uint8Array
          const wrappedKeyBytes = new Uint8Array(msg.wrappedKey);

          // Unwrap the key using our private key
          const unwrappedKey = await crypto.subtle.unwrapKey(
            'raw',
            wrappedKeyBytes,
            wrappingKeyPair.privateKey,
            {
              name: 'RSA-OAEP',
            },
            { name: 'AES-GCM', length: 256 },
            false, // not extractable
            ['encrypt', 'decrypt'],
          );

          // Persist the unwrapped key
          await persistKey(unwrappedKey);

          // Clean up RSA keys after successful storage
          wrappingKeyPair = null;

          // Clean up sensitive data from the message
          secureCleanup(msg.wrappedKey);
          secureCleanup(wrappedKeyBytes);

          logInfo('Master key securely stored and RSA keys cleaned up');
          return { status: 'ok' };
        } catch (e: any) {
          logError('Failed to unwrap and store key', e);

          // Clean up on error too
          wrappingKeyPair = null;

          if (e instanceof DOMException) {
            switch (e.name) {
              case 'OperationError':
                return { error: 'Failed to unwrap key - invalid or corrupted data' };
              case 'DataError':
                return { error: 'Invalid key format' };
              default:
                return { error: `Crypto operation failed: ${e.name}` };
            }
          }

          return { error: 'Failed to store key securely' };
        }
      }

      // proxy → store.ts
      default:
        return handleMessageInBackground(msg);
    }
  } catch (e: any) {
    logError('router error', e);
    return { error: e?.message ?? String(e) };
  }
}

// Bootstrap
logInfo('bootstrap');
patchSelfSend(router);
browser.runtime.onMessage.addListener(router);

initializeAuthenticator();
loadMasterKey().catch(logError);

logInfo('ready');
