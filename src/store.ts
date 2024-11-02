import { 
  SecretKeyType, 
  SecretKey, 
  SigningAlgorithm, 
  ES256, 
  RS256 
} from './authenticator';

// Use the built-in browser API for cryptography
const crypto = window.crypto;
const subtle = crypto.subtle;

// Logging functions
function logInfo(message: string, data?: any) {
  if (data !== undefined) {
    console.log(`[Store] ${message}:`, data);
  } else {
    console.log(`[Store] ${message}`);
  }
}

function logError(message: string, error?: any) {
  console.error(`[Store Error] ${message}`, error);
}

// Interfaces
export interface StoredCredential {
  uniqueId: string;
  credentialId: string;
  rpId: string;
  userIdHash: string;
  privateKey: string;
  userHandle: string;
  userName: string;
  userDisplayName: string;
  publicKey: string;
  publicKeyAlgorithm: number;
  counter: number;
  createdAt: number;
}

export interface AuthenticatorAttestationResponse {
  type: string;
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    publicKeyAlgorithm: number;
  };
}

// The MemoryStore class remains unchanged
export class MemoryStore {
  private static instance: MemoryStore | null = null;
  private store: Map<string, AuthenticatorAttestationResponse>;

  private constructor() {
    this.store = new Map();
  }

  public static getInstance(): MemoryStore {
    if (!MemoryStore.instance) {
      MemoryStore.instance = new MemoryStore();
    }
    return MemoryStore.instance;
  }

  saveAttestationResponse(response: AuthenticatorAttestationResponse) {
    this.store.set(response.id, response);
    logInfo(`Attestation response saved`, { id: response.id });
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

// Functions for working with IndexedDB

// Define the database and store names
const DB_NAME = 'WebAuthnDB';
const DB_VERSION = 1;
const STORE_NAME = 'storedCredentials';

// Open the database
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        // Create an object store with uniqueId as the key
        db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// Add or update credentials
async function addOrUpdateCredential(credential: StoredCredential): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(credential);

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// Retrieve credentials by uniqueId
async function getCredentialById(uniqueId: string): Promise<StoredCredential | undefined> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(uniqueId);

    request.onsuccess = () => {
      resolve(request.result as StoredCredential | undefined);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// Retrieve all credentials
async function getAllCredentials(): Promise<StoredCredentials> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.getAll();

    request.onsuccess = () => {
      const result = request.result as StoredCredential[];
      const credentials: StoredCredentials = {};
      result.forEach(cred => {
        credentials[cred.uniqueId] = cred;
      });
      resolve(credentials);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// Delete credentials by uniqueId
async function deleteCredential(uniqueId: string): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(uniqueId);

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// Clear all credentials
async function clearCredentials(): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.clear();

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// Type for StoredCredentials
export interface StoredCredentials {
  [uniqueId: string]: StoredCredential;
}

// Asynchronous function to write credentials
export async function writeStoredCredentials(storedCredentials: StoredCredentials): Promise<void> {
  try {
    // Get all current credentials
    const existingCredentials = await getAllCredentials();

    // Update or add new credentials
    for (const uniqueId in storedCredentials) {
      existingCredentials[uniqueId] = storedCredentials[uniqueId];
      await addOrUpdateCredential(storedCredentials[uniqueId]);
    }

    logInfo('Stored credentials written', { count: Object.keys(storedCredentials).length });
  } catch (error) {
    logError('Error writing stored credentials', error);
    throw error;
  }
}

// Asynchronous function to read credentials
export async function readStoredCredentials(): Promise<StoredCredentials> {
  try {
    const storedCredentials = await getAllCredentials();
    const count = Object.keys(storedCredentials).length;
    if (count > 0) {
      logInfo('Stored credentials read', { count });
      logInfo('Stored credentials:', storedCredentials);
    } else {
      logInfo('No stored credentials found');
    }
    return storedCredentials;
  } catch (error) {
    logError('Error reading stored credentials', error);
    return {};
  }
}

// Asynchronous function to save a private key
export async function savePrivateKey(
  credentialId: Uint8Array,
  rpId: string,
  secretKey: SecretKey,
  userId: ArrayBuffer,
  publicKeyDer: ArrayBuffer,
  publicKeyAlgorithm: number,
  userIdHash: string | Promise<string>,
  userName: string,
  userDisplayName: string
): Promise<void> {
  logInfo('Saving private key');

  try {
    // Export the private key in PKCS#8 format
    const privateKeyExported = await subtle.exportKey('pkcs8', secretKey.key);
    logInfo('Private key exported successfully');

    // Encode the private key in base64url
    const privateKeyBase64 = base64UrlEncode(new Uint8Array(privateKeyExported));

    // Encode credentialId in base64url
    const credentialIdEncoded = base64UrlEncode(credentialId);
    const uniqueId = await createUniqueId(rpId, credentialIdEncoded);

    // Resolve userIdHash if it's a Promise
    const resolvedUserIdHash = await userIdHash;

    // Create a StoredCredential object
    const storedCredential: StoredCredential = {
      uniqueId,
      credentialId: credentialIdEncoded,
      rpId,
      userIdHash: resolvedUserIdHash,
      privateKey: privateKeyBase64,
      userHandle: base64UrlEncode(new Uint8Array(userId)),
      userName,
      userDisplayName,
      publicKey: base64UrlEncode(new Uint8Array(publicKeyDer)),
      publicKeyAlgorithm,
      counter: 0,
      createdAt: Date.now()
    };

    // Save credentials in IndexedDB
    await addOrUpdateCredential(storedCredential);
    logInfo('Private key saved', { credentialId: storedCredential.credentialId });
  } catch (error) {
    logError('Error saving private key', error);
    throw error;
  }
}

// Asynchronous function to load a private key
export async function loadPrivateKey(credentialId: string): Promise<[SecretKey, SigningAlgorithm, number]> {
  logInfo('Loading private key', { credentialId });

  try {
    // Get all credentials
    const storedCredentials = await readStoredCredentials();

    // Find the account by credentialId
    const credential = Object.values(storedCredentials).find(cred => cred.credentialId === credentialId);

    if (!credential) {
      logError('Private key not found', { credentialId });
      throw new Error('Private key not found');
    }

    // Decode the private key from base64url
    const privateKeyBuffer = base64UrlDecode(credential.privateKey);

    // Determine the algorithm
    const algorithm = credential.publicKeyAlgorithm === -7 ? new ES256() : new RS256();
    const keyType = algorithm instanceof ES256 ? 'ECDSA' : 'RSASSA-PKCS1-v1_5';

    // Import key parameters
    const importParams = algorithm instanceof ES256 
      ? { name: keyType, namedCurve: 'P-256' } 
      : { name: keyType, hash: 'SHA-256' };

    // Import the private key
    const key = await subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      importParams,
      false,
      ['sign']
    );

    const secretKey: SecretKey = { 
      type: algorithm instanceof ES256 ? SecretKeyType.Ecdsa : SecretKeyType.Rsa, 
      key 
    };

    logInfo('Private key loaded successfully', { algorithm: keyType });

    return [secretKey, algorithm, credential.counter];
  } catch (error) {
    logError('Error loading private key', error);
    throw error;
  }
}

// Asynchronous function to find credentials
export async function findCredential(options: PublicKeyCredentialRequestOptions): Promise<StoredCredential> {
  const rpId = options.rpId || new URL(options.origin).hostname;
  const storedCredentials = await readStoredCredentials();

  logInfo('Searching for credential', { rpId });

  let matchingCredential: StoredCredential | null = null;

  if (options.publicKey?.allowCredentials?.length > 0) {
    // If there are allowCredentials, then look for a specific one
    for (const allowedCred of options.publicKey.allowCredentials) {
      const credentialIdEncoded = typeof allowedCred.id === 'string' 
        ? allowedCred.id 
        : base64UrlEncode(new Uint8Array(allowedCred.id));
      
      logInfo('Credential ID for search:', { credentialIdEncoded });
      
      const uniqueId = await createUniqueId(rpId, credentialIdEncoded);
      logInfo('Searching for uniqueId:', { uniqueId });

      if (storedCredentials[uniqueId]) {
        matchingCredential = storedCredentials[uniqueId];
        logInfo('Matching credential found', { uniqueId, credentialId: matchingCredential.credentialId });
        break;
      } else {
        logInfo('No matching credential for uniqueId', { uniqueId });
      }
    }
  } else {
    // If allowCredentials is empty, find all credentials for this domain
    const credentials = Object.values(storedCredentials)
      .filter(cred => cred.rpId === rpId);
    
    // Sorting by creation time (new to old)
    credentials.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)); 
    
    if (credentials.length > 0) {
      matchingCredential = credentials[0];  // Take the most recently created credential
      logInfo('Found credentials for domain', { 
        totalFound: credentials.length,
        selectedCredential: matchingCredential.userName,
        createdAt: new Date(matchingCredential.createdAt).toLocaleString()
      });
    }
  }

  if (matchingCredential) {
    logInfo('Credential found', { 
      credentialId: matchingCredential.credentialId, 
      userName: matchingCredential.userName, 
      userDisplayName: matchingCredential.userDisplayName,
      createdAt: new Date(matchingCredential.createdAt).toLocaleString()
    });
    return matchingCredential;
  }

  logError('No matching credential found', { rpId });
  throw new Error('No matching credential found');
}

export async function getUserNameFromOptions(options: PublicKeyCredentialRequestOptions): Promise<string | null> {
  try {
    const storedCredential = await findCredential(options);
    if (storedCredential) {
      logInfo('Retrieved credential for display', { 
        userName: storedCredential.userName, 
        userDisplayName: storedCredential.userDisplayName,
        credentialId: storedCredential.credentialId
      });
      return storedCredential.userName || storedCredential.userDisplayName || null;
    }
    return null;
  } catch (error) {
    logError('Error in getUserNameFromOptions', error);
    return null;
  }
}

// Asynchronous function to generate a user ID hash
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

// Asynchronous function to update the account counter
export async function updateCredentialCounter(credentialId: string): Promise<void> {
  logInfo('Updating credential counter', { credentialId });

  try {
    const storedCredentials = await readStoredCredentials();
    for (const uniqueId in storedCredentials) {
      if (storedCredentials[uniqueId].credentialId === credentialId) {
        storedCredentials[uniqueId].counter++;
        await addOrUpdateCredential(storedCredentials[uniqueId]);
        logInfo('Credential counter updated', { credentialId, newCounter: storedCredentials[uniqueId].counter });
        return;
      }
    }
    
    logError('Credential not found for updating counter', { credentialId });
    throw new Error('Credential not found for updating counter');
  } catch (error) {
    logError('Error updating credential counter', error);
    throw error;
  }
}

// Asynchronous function to create a unique identifier
export async function createUniqueId(rpId: string, credentialId: string): Promise<string> {
  const combinedString = `${rpId}:${credentialId}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(combinedString);
  
  const hash = await subtle.digest('SHA-256', data);
  
  const uniqueId = base64UrlEncode(new Uint8Array(hash));
  logInfo('Unique ID generated', { uniqueId });
  return uniqueId;
}

// Base64 URL encoding and decoding functions
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
    console.error('Error in base64UrlDecode:', error);
    throw error;
  }
}
