import { base64UrlToArrayBuffer } from './base64url';
import { handleMessageInBackground, saveStoredCredential, getSettings } from './store';
import {
  initializeAuthenticator,
  createCredential,
  handleGetAssertion,
  getAvailableCredentials,
} from './authenticator';

// Import the upload function
import { uploadPasskeyToRenterd } from './sia';
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
 * @param options - The options object to deserialize.
 */
function deserializeOptions(options: any): any {
  const deserializedOptions = { ...options };

  if (options.publicKey) {
    deserializedOptions.publicKey = { ...options.publicKey };

    // Deserialize challenge
    if (typeof options.publicKey.challenge === 'string') {
      deserializedOptions.publicKey.challenge = base64UrlToArrayBuffer(
        options.publicKey.challenge
      );
    }

    // Deserialize user ID
    if (options.publicKey.user) {
      deserializedOptions.publicKey.user = { ...options.publicKey.user };
      if (options.publicKey.user.id) {
        if (typeof options.publicKey.user.id === 'string') {
          deserializedOptions.publicKey.user.id = base64UrlToArrayBuffer(
            options.publicKey.user.id
          );
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
      deserializedOptions.publicKey.excludeCredentials =
        options.publicKey.excludeCredentials.map((cred: any) => ({
          ...cred,
          id: base64UrlToArrayBuffer(cred.id),
        }));
    }

    // Deserialize allowCredentials IDs
    if (options.publicKey.allowCredentials) {
      deserializedOptions.publicKey.allowCredentials =
        options.publicKey.allowCredentials.map((cred: any) => ({
          ...cred,
          id: base64UrlToArrayBuffer(cred.id),
        }));
    }
  }

  // Copy origin
  deserializedOptions.origin = options.origin;

  return deserializedOptions;
}

/* ================================================
   Message Listener
=============================================== */

/**
 * Listener for messages from content scripts or the page.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.type) {
        case 'createCredential': {
          const options = deserializeOptions(message.options);
          const credential = await createCredential(options);
          sendResponse(credential);
          break;
        }
        case 'handleGetAssertion': {
          const options = deserializeOptions(message.options);
          const assertionResponse = await handleGetAssertion(
            options,
            message.selectedCredentialId
          );
          sendResponse(assertionResponse);
          break;
        }
        case 'getAvailableCredentials': {
          const accounts = await getAvailableCredentials(message.rpId);
          sendResponse(accounts);
          break;
        }
        case 'uploadToSia': {
          const passkey = message.passkeyData as StoredCredential;

          // Get renterd settings
          const settings = await getSettings();
          if (!settings) {
            sendResponse({
              success: false,
              error: 'Please configure renterd settings first.',
            });
            return;
          }

          // Prepare passkey data
          const passkeyDataJson = JSON.stringify(passkey, null, 2);
          const blob = new Blob([passkeyDataJson], { type: 'application/json' });

          // Perform the upload
          try {
            await uploadPasskeyToRenterd(blob, `${passkey.uniqueId}.json`, settings);

            // Update isSynced flag and save passkey
            passkey.isSynced = true;
            await saveStoredCredential(passkey);

            sendResponse({
              success: true,
              message: 'Passkey uploaded successfully to Sia.',
            });
          } catch (error: any) {
            console.error('Error uploading passkey:', error);
            sendResponse({
              success: false,
              error: `Failed to upload passkey: ${error.message}`,
            });
          }
          break;
        }
        default: {
          // Handle other message types
          const result = await handleMessageInBackground(message);
          sendResponse(result);
          break;
        }
      }
    } catch (error: any) {
      console.error('Error in background message handler:', error);
      sendResponse({ error: error.message });
    }
  })();
  return true; // Indicates that sendResponse will be called asynchronously
});