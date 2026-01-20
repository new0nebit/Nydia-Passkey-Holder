import browser from 'browser-api';

import {
  createCredential,
  getAvailableCredentials,
  handleGetAssertion,
} from './authenticator';
import { logDebug, logError, logInfo } from './logger';
import {
  downloadPasskeyFromRenterd,
  getPasskeysFromRenterd,
  uploadPasskeyDirect,
} from './sia';
import {
  getEncryptedCredentialByUniqueId,
  getSettings,
  handleMessageInBackground,
  isBackgroundContext,
  saveEncryptedCredential,
  getMasterKeyIfAvailable,
  setMasterKey,
} from './store';
import {
  BackgroundMessage,
  CredentialCreationOptions,
  EncryptedRecord,
  GetAssertionOptions,
  SerializedCreationOptions,
  SerializedCredentialDescriptor,
  SerializedRequestOptions,
} from './types';
import { toArrayBuffer } from './utils/buffer';

// RSA wrapping key pair for secure key transfer
let wrappingKeyPair: CryptoKeyPair | null = null;

// RSA key pair generation for secure key transfer
async function initializeWrappingKey(): Promise<CryptoKeyPair> {
  logDebug('[Background] Generating RSA-OAEP key pair for secure transfer');

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

  logDebug('[Background] RSA-OAEP key pair generated');
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
function patchSelfSend(local: (m: BackgroundMessage) => Promise<unknown>) {
  const rt = browser.runtime;
  if (!rt?.sendMessage) return;

  const myId = rt.id;
  const orig = rt.sendMessage.bind(rt);

  rt.sendMessage = ((...args: unknown[]) => {
    let extId: string | undefined;
    let msg: BackgroundMessage;

    if (args.length === 1) {
      msg = args[0] as BackgroundMessage;
    } else {
      extId = args[0] as string | undefined;
      msg = args[1] as BackgroundMessage;
    }

    return !extId || extId === myId
      ? local(msg)
      : orig(...(args as Parameters<typeof rt.sendMessage>));
  }) as typeof rt.sendMessage;

  logInfo('[Background] runtime.sendMessage patched');
}

function normalizeDescriptor(
  descriptors?: SerializedCredentialDescriptor[],
): PublicKeyCredentialDescriptor[] | undefined {
  return descriptors?.map((descriptor) => ({
    type: (descriptor.type ?? 'public-key') as PublicKeyCredentialType,
    id: toArrayBuffer(descriptor.id),
    transports: descriptor.transports as AuthenticatorTransport[] | undefined,
  }));
}

function toCreationOptions(options: SerializedCreationOptions): CredentialCreationOptions {
  const { publicKey } = options;

  if (!publicKey?.challenge) {
    throw new Error('Invalid options: challenge is required');
  }
  if (!publicKey.user) {
    throw new Error('Invalid options: user is required');
  }
  if (!publicKey.pubKeyCredParams) {
    throw new Error('Invalid options: pubKeyCredParams is required');
  }

  if (!publicKey.rp?.name) {
    throw new Error('Invalid options: rp.name is required');
  }

  const rpId = publicKey.rp.id ?? new URL(options.origin ?? '').hostname;

  const rpEntity: PublicKeyCredentialRpEntity = {
    id: rpId,
    name: publicKey.rp.name,
  };

  return {
    publicKey: {
      rp: rpEntity,
      rpId,
      challenge: toArrayBuffer(publicKey.challenge),
      user: {
        ...(publicKey.user as CredentialCreationOptions['publicKey']['user']),
        id: toArrayBuffer(publicKey.user.id),
      },
      pubKeyCredParams: publicKey.pubKeyCredParams,
      excludeCredentials: normalizeDescriptor(publicKey.excludeCredentials),
    },
    origin: options.origin ?? '',
  };
}

function toGetAssertionOptions(options: SerializedRequestOptions): GetAssertionOptions {
  const { publicKey } = options;

  if (!publicKey?.challenge) {
    throw new Error('Invalid options: challenge is required');
  }

  const rpId = publicKey.rpId ?? new URL(options.origin ?? '').hostname;

  return {
    publicKey: {
      ...publicKey,
      rpId,
      challenge: toArrayBuffer(publicKey.challenge),
      allowCredentials: normalizeDescriptor(publicKey.allowCredentials),
    },
    origin: options.origin ?? '',
  };
}

// Checks if the given object is a valid EncryptedRecord
function isValidEncryptedRecord(x: unknown): x is EncryptedRecord {
  return Boolean(x && typeof x === 'object' && 'uniqueId' in x && 'iv' in x && 'data' in x);
}

// Type guard for BackgroundMessage
function isBackgroundMessage(msg: unknown): msg is BackgroundMessage {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    'type' in msg &&
    typeof (msg as { type: unknown }).type === 'string'
  );
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
  let uploaded = 0,
    failed = 0;

  for (const uniqueId of uniqueIds) {
    try {
      const { success } = await handleUploadToSia(uniqueId);
      if (success) uploaded++;
      else failed++;
    } catch (e) {
      logError(`[Background] Upload failed for ${uniqueId}`, e);
      failed++;
    }
  }

  return { success: failed === 0, uploadedCount: uploaded, failedCount: failed };
}

// Handles syncing passkeys from renterd to the extension
async function handleSyncFromSia() {
  const settings = await getSettings();
  if (!settings) return { success: false, error: 'No renterd settings' };

  const files = await getPasskeysFromRenterd(settings);
  let synced = 0,
    failed = 0;

  for (const fileName of files) {
    try {
      const encryptedRecord = await downloadPasskeyFromRenterd(fileName, settings);

      if (!isValidEncryptedRecord(encryptedRecord)) {
        failed++;
        continue;
      }

      // Save encrypted record directly to DB
      await saveEncryptedCredential(encryptedRecord);
      synced++;
    } catch (e) {
      logError(`[Background] Sync failed for ${fileName}`, e);
      failed++;
    }
  }
  return { success: failed === 0, syncedCount: synced, failedCount: failed };
}

// Router
async function router(msg: BackgroundMessage): Promise<unknown> {
  try {
    switch (msg.type) {
      case 'createCredential':
        if (!(await getMasterKeyIfAvailable())) return { error: 'masterKeyMissing' };
        if (!msg.options?.publicKey) return { error: 'Invalid options: publicKey is required' };
        return createCredential(toCreationOptions(msg.options as SerializedCreationOptions));

      case 'handleGetAssertion':
        if (!(await getMasterKeyIfAvailable())) return { error: 'masterKeyMissing' };
        if (!msg.options?.publicKey) return { error: 'Invalid options: publicKey is required' };
        return handleGetAssertion(
          toGetAssertionOptions(msg.options as SerializedRequestOptions),
          msg.selectedCredentialId,
        );

      case 'getAvailableCredentials':
        if (!msg.rpId) return { error: 'Missing rpId' };
        return getAvailableCredentials(msg.rpId);

      // Use uniqueId
      case 'uploadToSia':
        if (!msg.uniqueId) return { error: 'Missing uniqueId' };
        return handleUploadToSia(msg.uniqueId);

      case 'uploadUnsyncedPasskeys':
        if (!msg.uniqueIds) return { error: 'Missing uniqueIds' };
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
        } catch (e: unknown) {
          logError('[Background] Failed to export public key', e);
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
          await setMasterKey(unwrappedKey);

          // Clean up RSA keys after successful storage
          wrappingKeyPair = null;

          // Clean up sensitive data from the message
          secureCleanup(msg.wrappedKey);
          secureCleanup(wrappedKeyBytes);

          logDebug('[Background] Master key securely stored and RSA keys cleaned up');
          return { status: 'ok' };
        } catch (e: unknown) {
          logError('[Background] Failed to unwrap and store key', e);

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
  } catch (e: unknown) {
    logError('[Background] router error', e);
    const message = e instanceof Error ? e.message : String(e);
    return { error: message };
  }
}

// Bootstrap
logInfo('[Background] bootstrap');
logDebug('[Background] isBackgroundContext', isBackgroundContext());

patchSelfSend(router);
browser.runtime.onMessage.addListener((message: unknown) => {
  if (!isBackgroundMessage(message)) {
    logError('[Background] Invalid message format', message);
    return Promise.resolve({ error: 'Invalid message format' });
  }
  return router(message);
});

getMasterKeyIfAvailable().catch(logError);
logInfo('[Background] ready');
