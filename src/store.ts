import { SigningAlgorithm, ES256, RS256 } from './algorithms';
import { StoredCredential, RenterdSettings } from './types';
import { logInfo, logError } from './logger';

// Web Crypto API
const crypto = self.crypto;
const subtle = crypto.subtle;

/* ================================================
   Helper Functions
=============================================== */

/**
 * Checks if the current context is the background script.
 */
function isBackgroundContext(): boolean {
  return (
    typeof chrome !== 'undefined' &&
    !!chrome.runtime &&
    !!chrome.runtime.id &&
    typeof window === 'undefined'
  );
}

/**
 * Sends a message to the background script or handles it directly if in the background context.
 */
function sendMessageToExtension(message: any): Promise<any> {
  return new Promise(async (resolve, reject) => {
    if (isBackgroundContext()) {
      // Handle message directly in the background script
      try {
        const response = await handleMessageInBackground(message);
        resolve(response);
      } catch (error) {
        logError('Error handling message in background script', error);
        reject(error);
      }
    } else if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
      // Send message to the background script
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          logError('Error sending message to extension', {
            message: chrome.runtime.lastError.message,
            error: chrome.runtime.lastError,
          });
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    } else {
      logError('chrome.runtime is not available');
      reject(new Error('chrome.runtime is not available'));
    }
  });
}

/* ================================================
   IndexedDB Operations
================================================ */

const DB_NAME = 'NydiaDB';
const DB_VERSION = 3;
const STORE_NAME = 'storedCredentials';

/**
 * Opens the IndexedDB database.
 */
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      let objectStore: IDBObjectStore;

      if (!db.objectStoreNames.contains(STORE_NAME)) {
        objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
        console.log('Created new object store:', STORE_NAME);
      } else {
        const transaction = request.transaction;
        if (!transaction) {
          const error = new Error('Transaction is undefined in onupgradeneeded event.');
          console.error(error);
          reject(error);
          return;
        }
        objectStore = transaction.objectStore(STORE_NAME);
        console.log('Using existing object store:', STORE_NAME);
      }

      // Create indexes if they don't exist
      if (!objectStore.indexNames.contains('credentialId')) {
        objectStore.createIndex('credentialId', 'credentialId', { unique: true });
        console.log('Created credentialId index');
      }
      if (!objectStore.indexNames.contains('rpId')) {
        objectStore.createIndex('rpId', 'rpId', { unique: false });
        console.log('Created rpId index');
      }

      // Handle settings store
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'id' });
        console.log('Created settings store');
      }
    };

    request.onsuccess = () => {
      console.log('Database opened successfully');
      resolve(request.result);
    };

    request.onerror = () => {
      console.error('Error opening database:', request.error);
      reject(request.error);
    };
  });
}

/* ================================================
   Settings Management
================================================ */

/**
 * Saves the settings to the IndexedDB.
 */
export async function saveSettings(settings: RenterdSettings): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('settings', 'readwrite');
    const store = transaction.objectStore('settings');
    const request = store.put({ ...settings, id: 'renterdSettings' });

    request.onsuccess = () => {
      console.log('Settings saved successfully.');
      resolve();
    };

    request.onerror = () => {
      console.error('Error saving settings:', request.error);
      reject(request.error);
    };
  });
}

/**
 * Retrieves the settings from the IndexedDB.
 */
export async function getSettings(): Promise<RenterdSettings | null> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('settings', 'readonly');
    const store = transaction.objectStore('settings');
    const request = store.get('renterdSettings');

    request.onsuccess = () => {
      resolve((request.result as RenterdSettings) || null);
    };

    request.onerror = () => {
      console.error('Error retrieving settings:', request.error);
      reject(request.error);
    };
  });
}

/* ================================================
   Stored Credential Management
================================================ */

/**
 * Saves a StoredCredential to the IndexedDB.
 */
export async function saveStoredCredential(storedCredential: StoredCredential): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(storedCredential);

    request.onsuccess = () => {
      logInfo('StoredCredential saved successfully:', storedCredential.uniqueId);
      resolve();
    };

    request.onerror = () => {
      logError('Error saving StoredCredential:', request.error);
      reject(request.error);
    };
  });
}

/**
 * Retrieves a StoredCredential by credentialId.
 */
export async function getStoredCredentialByCredentialId(credentialId: string): Promise<StoredCredential | undefined> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('credentialId');
    const request = index.get(credentialId);

    request.onsuccess = () => {
      resolve(request.result as StoredCredential | undefined);
    };

    request.onerror = () => {
      logError('Error getting StoredCredential by credentialId:', request.error);
      reject(request.error);
    };
  });
}

/**
 * Retrieves all StoredCredentials from the IndexedDB.
 */
export async function getAllStoredCredentialsFromDB(): Promise<StoredCredential[]> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.getAll();

    request.onsuccess = () => {
      resolve(request.result as StoredCredential[]);
    };

    request.onerror = () => {
      logError('Error getting all StoredCredentials:', request.error);
      reject(request.error);
    };
  });
}

/**
 * Finds a StoredCredential based on options and an optional selectedCredentialId.
 */
export async function findStoredCredential(
  options: any,
  selectedCredentialId?: string
): Promise<StoredCredential | undefined> {
  const db = await openDatabase();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.getAll();

    request.onsuccess = () => {
      const storedCredentials = request.result as StoredCredential[];
      let matchingCredential: StoredCredential | undefined;

      const rpId = options.rpId || new URL(options.origin).hostname;

      if (selectedCredentialId) {
        // Find by selectedCredentialId
        matchingCredential = storedCredentials.find(
          (cred) => cred.credentialId === selectedCredentialId && cred.rpId === rpId
        );
        if (matchingCredential) {
          logInfo('Matching credential found by selectedCredentialId:', matchingCredential.credentialId);
        }
      } else if (options.allowCredentials && options.allowCredentials.length > 0) {
        // Find by allowed credentials
        for (const allowedCred of options.allowCredentials) {
          const credentialIdEncoded =
            typeof allowedCred.id === 'string'
              ? allowedCred.id
              : base64UrlEncode(new Uint8Array(allowedCred.id));

          matchingCredential = storedCredentials.find(
            (cred) => cred.credentialId === credentialIdEncoded && cred.rpId === rpId
          );

          if (matchingCredential) {
            logInfo('Matching credential found:', matchingCredential.credentialId);
            break;
          }
        }
      } else {
        // Find by rpId if allowCredentials is not provided
        matchingCredential = storedCredentials.find((cred) => cred.rpId === rpId);
        if (matchingCredential) {
          logInfo('Credential found by rpId:', matchingCredential.credentialId);
        }
      }

      if (matchingCredential) {
        resolve(matchingCredential);
      } else {
        logError('No matching credential found for rpId:', rpId);
        resolve(undefined);
      }
    };

    request.onerror = () => {
      logError('Error finding StoredCredential:', request.error);
      reject(request.error);
    };
  });
}

/**
 * Updates the counter of a StoredCredential.
 */
export async function updateCredentialCounter(credentialId: string): Promise<void> {
  const db = await openDatabase();

  const storedCredential = await getStoredCredentialByCredentialId(credentialId);

  if (!storedCredential) {
    logError('Credential not found for updating counter:', credentialId);
    throw new Error('Credential not found for updating counter');
  }

  storedCredential.counter++;

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(storedCredential);

    request.onsuccess = () => {
      logInfo('Credential counter updated:', {
        credentialId,
        newCounter: storedCredential.counter,
      });
      resolve();
    };

    request.onerror = () => {
      logError('Error updating credential counter:', request.error);
      reject(request.error);
    };
  });
}

/* ================================================
   Messaging in Background Context
================================================ */

/**
 * Handles messages directly in the background script.
 */
export async function handleMessageInBackground(message: any): Promise<any> {
  switch (message.type) {
    case 'saveStoredCredential':
      await saveStoredCredential(message.storedCredential);
      return { status: 'success' };
    case 'getStoredCredential':
      const storedCredential = await getStoredCredentialByCredentialId(
        message.credentialId
      );
      return storedCredential || { error: 'Credential not found' };
    case 'findCredential':
      const foundCredential = await findStoredCredential(
        message.options,
        message.selectedCredentialId
      );
      return foundCredential || { error: 'Credential not found' };
    case 'updateCredentialCounter':
      await updateCredentialCounter(message.credentialId);
      return { status: 'success' };
    case 'getAllStoredCredentials':
      const storedCredentials = await getAllStoredCredentialsFromDB();
      return storedCredentials;
    default:
      throw new Error('Unknown message type');
  }
}

/* ================================================
   MemoryStore Class
================================================ */

export class MemoryStore {
  private static instance: MemoryStore | null = null;
  private store: Map<string, any>;

  private constructor() {
    this.store = new Map();
  }

  public static getInstance(): MemoryStore {
    if (!MemoryStore.instance) {
      MemoryStore.instance = new MemoryStore();
    }
    return MemoryStore.instance;
  }

  saveAttestationResponse(response: any) {
    this.store.set(response.id, response);
    logInfo('Attestation response saved', { id: response.id });
  }

  getAttestationResponse(id: string) {
    return this.store.get(id);
  }

  getAllAttestationResponses() {
    return Array.from(this.store.values());
  }

  deleteAttestationResponse(id: string) {
    return this.store.delete(id);
  }

  clearStore() {
    this.store.clear();
    logInfo('MemoryStore cleared');
  }
}

export function getMemoryStore(): MemoryStore {
  return MemoryStore.getInstance();
}

/* ================================================
   Utility Functions
================================================ */

/**
 * Encodes an ArrayBuffer or Uint8Array to a base64url string.
 */
export function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decodes a base64url string to a Uint8Array.
 */
export function base64UrlDecode(str: string): Uint8Array {
  if (!str) {
    console.warn('base64UrlDecode received empty input');
    return new Uint8Array(0);
  }
  try {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
      str += '=';
    }
    const binStr = atob(str);
    const buf = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      buf[i] = binStr.charCodeAt(i);
    }
    return buf;
  } catch (error) {
    logError('Error in base64UrlDecode:', error);
    throw error;
  }
}

/**
 * Creates a unique identifier based on rpId and credentialId.
 */
export async function createUniqueId(rpId: string, credentialId: string): Promise<string> {
  const combinedString = `${rpId}:${credentialId}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(combinedString);

  const hash = await subtle.digest('SHA-256', data);

  const uniqueId = base64UrlEncode(new Uint8Array(hash));
  logInfo('Unique ID generated', { uniqueId });
  return uniqueId;
}

/**
 * Generates a hash of the user ID.
 */
export async function generateUserIdHash(rpId: string, userId: ArrayBuffer | string): Promise<string> {
  logInfo('Generating user ID hash');

  let userIdEncoded: string;
  if (userId instanceof ArrayBuffer) {
    userIdEncoded = base64UrlEncode(new Uint8Array(userId));
  } else {
    userIdEncoded = userId;
  }

  const combinedString = `${rpId}:${userIdEncoded}`;

  const encoder = new TextEncoder();
  const data = encoder.encode(combinedString);

  const hash = await subtle.digest('SHA-256', data);

  const userIdHash = base64UrlEncode(new Uint8Array(hash));
  logInfo('User ID hash generated');
  return userIdHash;
}

/* ================================================
   Private Key Management
================================================ */

/**
 * Saves the private key and related information.
 */
export async function savePrivateKey(
  credentialId: Uint8Array,
  rpId: string,
  privateKey: CryptoKey,
  userId: Uint8Array,
  cosePublicKey: Uint8Array,
  publicKeyAlgorithm: number,
  userIdHash: string,
  userName?: string
): Promise<void> {
  logInfo('Saving private key');

  try {
    // Export private key in PKCS#8 format
    const privateKeyExported = await subtle.exportKey('pkcs8', privateKey);
    logInfo('Private key exported successfully');

    // Encode private key and credentialId in base64url
    const privateKeyBase64 = base64UrlEncode(new Uint8Array(privateKeyExported));
    const credentialIdEncoded = base64UrlEncode(credentialId);
    const uniqueId = await createUniqueId(rpId, credentialIdEncoded);

    // Create StoredCredential object
    const storedCredential: StoredCredential = {
      uniqueId,
      credentialId: credentialIdEncoded,
      rpId,
      userIdHash,
      privateKey: privateKeyBase64,
      userHandle: base64UrlEncode(userId),
      publicKey: base64UrlEncode(cosePublicKey),
      publicKeyAlgorithm,
      counter: 0,
      userName,
    };

    // Save StoredCredential via extension
    await sendMessageToExtension({
      type: 'saveStoredCredential',
      storedCredential,
    });

    logInfo('Private key saved via extension', { credentialId: storedCredential.credentialId });
  } catch (error) {
    logError('Error saving private key via extension', error);
    throw error;
  }
}

/**
 * Loads the private key and related information.
 */
export async function loadPrivateKey(credentialId: string): Promise<[CryptoKey, SigningAlgorithm, number]> {
  logInfo('Loading private key', { credentialId });

  try {
    // Retrieve StoredCredential via extension
    const storedCredentialResponse = await sendMessageToExtension({
      type: 'getStoredCredential',
      credentialId,
    });

    if (storedCredentialResponse && storedCredentialResponse.error) {
      logError('Private key not found in extension', { credentialId });
      throw new Error('Private key not found');
    }

    const storedCredential = storedCredentialResponse as StoredCredential;

    // Decode private key
    const privateKeyBuffer = base64UrlDecode(storedCredential.privateKey);

    // Determine algorithm
    const algorithm =
      storedCredential.publicKeyAlgorithm === -7 ? new ES256() : new RS256();
    const keyType = algorithm instanceof ES256 ? 'ECDSA' : 'RSASSA-PKCS1-v1_5';

    // Import private key
    const importParams =
      algorithm instanceof ES256
        ? { name: keyType, namedCurve: 'P-256' }
        : { name: keyType, hash: 'SHA-256' };

    const privateKey = await subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      importParams,
      false,
      ['sign']
    );

    logInfo('Private key loaded successfully from extension', { algorithm: keyType });

    return [privateKey, algorithm, storedCredential.counter];
  } catch (error) {
    logError('Error loading private key from extension', error);
    throw error;
  }
}

/**
 * Finds a credential based on options and an optional selectedCredentialId.
 */
export async function findCredential(
  options: any,
  selectedCredentialId?: string
): Promise<StoredCredential> {
  logInfo('Searching for credential via extension');

  try {
    const storedCredentialResponse = await sendMessageToExtension({
      type: 'findCredential',
      options,
      selectedCredentialId,
    });

    if (storedCredentialResponse && storedCredentialResponse.error) {
      throw new Error('No matching credential found via extension');
    }

    const storedCredential = storedCredentialResponse as StoredCredential;

    logInfo('Credential found via extension', {
      credentialId: storedCredential.credentialId,
    });
    return storedCredential;
  } catch (error) {
    logError('Error finding credential via extension', error);
    throw error;
  }
}

/**
 * Updates the credential counter via extension.
 */
export async function updateCredentialCounterViaExtension(credentialId: string): Promise<void> {
  logInfo('Updating credential counter via extension', { credentialId });

  try {
    const response = await sendMessageToExtension({
      type: 'updateCredentialCounter',
      credentialId,
    });

    if (response && response.status === 'success') {
      logInfo('Credential counter updated successfully via extension', { credentialId });
    } else {
      logError('Failed to update credential counter via extension', response);
      throw new Error('Failed to update credential counter');
    }
  } catch (error) {
    logError('Error updating credential counter via extension', error);
    throw error;
  }
}

/**
 * Retrieves all stored credentials via extension.
 */
export async function getAllStoredCredentials(): Promise<StoredCredential[]> {
  logInfo('Requesting all stored credentials via extension');

  try {
    const storedCredentialsResponse = await sendMessageToExtension({
      type: 'getAllStoredCredentials',
    });

    if (storedCredentialsResponse && storedCredentialsResponse.error) {
      logError('Error retrieving stored credentials via extension', storedCredentialsResponse.error);
      throw new Error('Error retrieving stored credentials');
    }

    const storedCredentials = storedCredentialsResponse as StoredCredential[];

    logInfo(`Retrieved ${storedCredentials.length} stored credentials via extension`);
    return storedCredentials;
  } catch (error) {
    logError('Error getting all stored credentials from extension', error);
    throw error;
  }
}
