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
  getEncryptedRecord,
  getSettings,
  handleMessageInBackground,
  saveEncryptedRecord,
  getRootKeyIfAvailable,
  setRootKey,
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
    false, // private key not extractable
    ['wrapKey', 'unwrapKey'],
  );

  logDebug('[Background] RSA-OAEP key pair generated');
  return keyPair;
}

function secureCleanup(data: Uint8Array | null): void {
  data?.fill(0);
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
  const { origin } = options;

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

  if (!origin) {
    throw new Error('Invalid options: origin is required');
  }

  const rpId = publicKey.rp.id ?? new URL(origin).hostname;

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
    origin,
  };
}

function toGetAssertionOptions(options: SerializedRequestOptions): GetAssertionOptions {
  const { publicKey } = options;
  const { origin } = options;

  if (!publicKey?.challenge) {
    throw new Error('Invalid options: challenge is required');
  }

  if (!origin) {
    throw new Error('Invalid options: origin is required');
  }

  const rpId = publicKey.rpId ?? new URL(origin).hostname;

  return {
    publicKey: {
      ...publicKey,
      rpId,
      challenge: toArrayBuffer(publicKey.challenge),
      allowCredentials: normalizeDescriptor(publicKey.allowCredentials),
    },
    origin,
  };
}

// Checks if the given object is a valid EncryptedRecord
function isValidEncryptedRecord(value: unknown): value is EncryptedRecord {
  return Boolean(
    value &&
      typeof value === 'object' &&
      'uniqueId' in value &&
      typeof (value as { uniqueId: unknown }).uniqueId === 'string' &&
      'metadata' in value &&
      'secret' in value &&
      'isSynced' in value &&
      typeof (value as { isSynced: unknown }).isSynced === 'boolean'
  );
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
  const encryptedRecord = await getEncryptedRecord(uniqueId);
  if (!encryptedRecord) {
    return { success: false, error: 'Passkey not found' };
  }

  // Upload encrypted record as-is
  const result = await uploadPasskeyDirect(encryptedRecord);

  // If upload successful, update isSynced flag
  if (result.success) {
    encryptedRecord.isSynced = true;
    await saveEncryptedRecord(encryptedRecord);
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
    } catch (error: unknown) {
      logError(`[Background] Upload failed for ${uniqueId}`, error);
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
      await saveEncryptedRecord(encryptedRecord);
      synced++;
    } catch (error: unknown) {
      logError(`[Background] Sync failed for ${fileName}`, error);
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
        if (!(await getRootKeyIfAvailable())) return { error: 'rootKeyMissing' };
        if (!msg.options?.publicKey) return { error: 'Invalid options: publicKey is required' };
        return await createCredential(toCreationOptions(msg.options as SerializedCreationOptions));

      case 'handleGetAssertion':
        if (!(await getRootKeyIfAvailable())) return { error: 'rootKeyMissing' };
        if (!msg.options?.publicKey) return { error: 'Invalid options: publicKey is required' };
        if (!msg.selectedUniqueId) return { error: 'Missing selectedUniqueId' };
        return await handleGetAssertion(
          toGetAssertionOptions(msg.options as SerializedRequestOptions),
          msg.selectedUniqueId,
        );

      case 'getAvailableCredentials':
        if (!msg.rpId) return { error: 'Missing rpId' };
        return await getAvailableCredentials(
          msg.rpId,
          Array.isArray(msg.allowCredentialIds) ? msg.allowCredentialIds : undefined,
        );

      // Use uniqueId
      case 'uploadToSia':
        if (!msg.uniqueId) return { error: 'Missing uniqueId' };
        return await handleUploadToSia(msg.uniqueId);

      case 'uploadUnsyncedPasskeys':
        if (!msg.uniqueIds) return { error: 'Missing uniqueIds' };
        return await handleUploadUnsyncedPasskeys(msg.uniqueIds);

      case 'syncFromSia':
        return await handleSyncFromSia();

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
        } catch (error: unknown) {
          logError('[Background] Failed to export public key', error);
          return { error: 'Failed to generate wrapping key' };
        }
      }

      // Store wrapped key using RSA-OAEP
      case 'storeWrappedKey': {
        let wrappedKeyBytes: Uint8Array | null = null;

        try {
          // Validate input
          if (!Array.isArray(msg.wrappedKey)) {
            return { error: 'Invalid wrapped key format' };
          }

          if (!wrappingKeyPair) {
            return { error: 'Wrapping key pair not initialized' };
          }

          // Convert array back to Uint8Array
          wrappedKeyBytes = new Uint8Array(msg.wrappedKey);

          // Unwrap the key using our private key
          const rootKey = await crypto.subtle.unwrapKey(
            'raw',
            wrappedKeyBytes as BufferSource,
            wrappingKeyPair.privateKey,
            { name: 'RSA-OAEP' },
            { name: 'HKDF' },
            false, // not extractable
            ['deriveKey'],
          );

          // Persist the root key
          await setRootKey(rootKey);

          // Clean up RSA keys after successful storage
          wrappingKeyPair = null;

          logDebug('[Background] Root key securely stored and RSA keys cleaned up');
          return { status: 'ok' };
        } catch (error: unknown) {
          logError('[Background] Failed to unwrap and store key', error);

          // Clean up on error too
          wrappingKeyPair = null;

          if (error instanceof DOMException) {
            switch (error.name) {
              case 'OperationError':
                return { error: 'Failed to unwrap key - invalid or corrupted data' };
              case 'DataError':
                return { error: 'Invalid key format' };
              default:
                return { error: `Crypto operation failed: ${error.name}` };
            }
          }

          return { error: 'Failed to store key securely' };
        } finally {
          if (wrappedKeyBytes) {
            secureCleanup(wrappedKeyBytes);
          }
        }
      }

      // proxy → store.ts
      default:
        return await handleMessageInBackground(msg);
    }
  } catch (error: unknown) {
    const isExpectedInvalidStateError =
      error instanceof DOMException && error.name === 'InvalidStateError';

    if (!isExpectedInvalidStateError) {
      logError('[Background] router error', error);
    }

    const message = error instanceof Error ? error.message : String(error);
    return { error: message };
  }
}

// Bootstrap
logInfo('[Background] bootstrap');
browser.runtime.onMessage.addListener((message: unknown) => {
  if (!isBackgroundMessage(message)) {
    logError('[Background] Invalid message format', message);
    return Promise.resolve({ error: 'Invalid message format' });
  }
  return router(message);
});

getRootKeyIfAvailable().catch(logError);
logInfo('[Background] ready');
