import browser from 'browser-api';

import {
  createCredential,
  getAvailableCredentials,
  handleGetAssertion,
  initializeAuthenticator,
} from './authenticator';
import { base64UrlToArrayBuffer } from './base64url';
import { logError, logInfo } from './logger';
import { downloadPasskeyFromRenterd, getPasskeysFromRenterd, uploadPasskeyDirect } from './sia';
import { handleMessageInBackground, getSettings, saveStoredCredential } from './store';
import { StoredCredential } from './types';

/**
 * Initializes the WebAuthn authenticator when the background script starts.
 */
initializeAuthenticator();

/* ================================================
  Utility Functions
=============================================== */

/**
 * Deserializes the options object by converting base64url strings to ArrayBuffers.
 */
function deserializeOptions(options: any): any {
  const deserializedOptions = { ...options };

  if (options.publicKey) {
    deserializedOptions.publicKey = { ...options.publicKey };

    // Deserialize challenge
    if (typeof options.publicKey.challenge === 'string') {
      deserializedOptions.publicKey.challenge = base64UrlToArrayBuffer(options.publicKey.challenge);
    }

    // Deserialize user ID
    if (options.publicKey.user) {
      deserializedOptions.publicKey.user = { ...options.publicKey.user };
      if (options.publicKey.user.id) {
        if (typeof options.publicKey.user.id === 'string') {
          deserializedOptions.publicKey.user.id = base64UrlToArrayBuffer(options.publicKey.user.id);
        } else if (
          ArrayBuffer.isView(options.publicKey.user.id) ||
          options.publicKey.user.id instanceof ArrayBuffer
        ) {
          deserializedOptions.publicKey.user.id = options.publicKey.user.id;
        } else {
          throw new Error('publicKey.user.id must be a string or ArrayBuffer');
        }
      }
    }

    // Deserialize excludeCredentials IDs
    if (options.publicKey.excludeCredentials) {
      deserializedOptions.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(
        (cred: any) => ({
          ...cred,
          id: base64UrlToArrayBuffer(cred.id),
        }),
      );
    }

    // Deserialize allowCredentials IDs
    if (options.publicKey.allowCredentials) {
      deserializedOptions.publicKey.allowCredentials = options.publicKey.allowCredentials.map(
        (cred: any) => ({
          ...cred,
          id: base64UrlToArrayBuffer(cred.id),
        }),
      );
    }
  }

  // Copy origin
  deserializedOptions.origin = options.origin;

  return deserializedOptions;
}

/**
 * Checks if the given object is a valid StoredCredential.
 */
function isPasskeyValid(passkey: any): passkey is StoredCredential {
  const requiredFields = [
    'uniqueId',
    'credentialId',
    'rpId',
    'userIdHash',
    'privateKey',
    'userHandle',
    'publicKey',
    'publicKeyAlgorithm',
    'counter',
  ];

  return requiredFields.every((field) => field in passkey);
}

/**
 * Handles the upload of a single passkey to renterd.
 */
async function handleUploadToSia(passkey: StoredCredential) {
  return await uploadPasskeyDirect(passkey);
}

/**
 * Handles syncing passkeys from renterd to the extension.
 */
async function handleSyncFromSia() {
  const settings = await getSettings();
  if (!settings) {
    return {
      success: false,
      error: 'Renterd settings not found',
    };
  }

  try {
    const remotePasskeys = await getPasskeysFromRenterd(settings);
    let syncedCount = 0;
    let failedCount = 0;

    for (const fileName of remotePasskeys) {
      try {
        const passkeyData = await downloadPasskeyFromRenterd(fileName, settings);

        if (!isPasskeyValid(passkeyData)) {
          logError('Invalid passkey data received from renterd', { fileName });
          failedCount++;
          continue;
        }

        passkeyData.isSynced = true;
        await saveStoredCredential(passkeyData);
        syncedCount++;
      } catch (error) {
        logError(`Error processing passkey ${fileName}`, error);
        failedCount++;
      }
    }

    logInfo('Sync from Sia completed', { syncedCount, failedCount });
    return {
      success: true,
      syncedCount,
      failedCount,
    };
  } catch (error: any) {
    logError('Error in syncFromSia operation', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to sync passkeys',
    };
  }
}

/**
 * Handles uploading multiple unsynced passkeys to renterd.
 */
async function handleUploadUnsyncedPasskeys(passkeys: StoredCredential[]) {
  let uploadedCount = 0;
  let failedCount = 0;

  for (const p of passkeys) {
    try {
      const result = await handleUploadToSia(p);
      if (result && result.success) {
        uploadedCount++;
      } else {
        failedCount++;
      }
    } catch (error) {
      logError('Error uploading unsynced passkey', { error, passkeyId: p.uniqueId });
      failedCount++;
    }
  }

  return {
    success: failedCount === 0,
    uploadedCount,
    failedCount,
  };
}

/* ================================================
  Message Listener
=============================================== */

browser.runtime.onMessage.addListener(async (message) => {
  try {
    switch (message.type) {
      case 'createCredential': {
        const options = deserializeOptions(message.options);
        const credential = await createCredential(options);
        return credential;
      }
      case 'handleGetAssertion': {
        const options = deserializeOptions(message.options);
        const assertionResponse = await handleGetAssertion(options, message.selectedCredentialId);
        return assertionResponse;
      }
      case 'getAvailableCredentials': {
        const accounts = await getAvailableCredentials(message.rpId);
        return accounts;
      }
      case 'uploadToSia': {
        const passkey = message.passkeyData as StoredCredential;
        return await handleUploadToSia(passkey);
      }
      case 'syncFromSia': {
        return await handleSyncFromSia();
      }
      case 'uploadUnsyncedPasskeys': {
        const passkeys = message.passkeys as StoredCredential[];
        return await handleUploadUnsyncedPasskeys(passkeys);
      }
      default: {
        const result = await handleMessageInBackground(message);
        return result;
      }
    }
  } catch (error: any) {
    logError('Error in background message handler', error);
    return { error: error.message };
  }
});
