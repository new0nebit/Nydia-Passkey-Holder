import browser from 'webextension-polyfill';

import { base64UrlEncode, base64UrlToArrayBuffer } from './base64url';
import { Account, WebAuthnOperationType } from './types';

// Define global popup interface for cross-script communication between content script and injected page script.
declare global {
  interface Window {
    nydiaPopup: {
      showPopup: (
        options: any,
        operationType: WebAuthnOperationType,
        onAction: (options: any, selectedCredentialId?: string) => Promise<any>,
        accounts?: Account[],
      ) => Promise<any>;
    };
  }
}

// Inject the injector.js script into the page to override WebAuthn methods.
const script = document.createElement('script');
script.src = browser.runtime.getURL('injector.js');
(document.head || document.documentElement).appendChild(script);
script.onload = () => {
  script.remove();
};

// Class responsible for intercepting and handling WebAuthn operations.
class WebAuthnInterceptor {
  private interceptEnabled = true;
  private createAbortController: AbortController | null = null;
  private getAbortController: AbortController | null = null;

  // Determines whether to intercept the WebAuthn operation.
  async shouldIntercept(): Promise<boolean> {
    return this.interceptEnabled;
  }

  // Intercepts navigator.credentials.create() calls.
  async interceptCreate(options: PublicKeyCredentialCreationOptions): Promise<Credential | null> {
    return this.interceptWebAuthn(options, 'create');
  }

  // Intercepts navigator.credentials.get() calls.
  async interceptGet(options: PublicKeyCredentialRequestOptions): Promise<Credential | null> {
    return this.interceptWebAuthn(options, 'get');
  }

  // General method to intercept WebAuthn operations.
  private async interceptWebAuthn(
    options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
    type: WebAuthnOperationType,
  ): Promise<Credential | null> {
    this.logDebug(`Intercepting WebAuthn operation: ${type}`);

    if (!options || typeof options !== 'object') {
      this.logDebug(`Invalid options for ${type}`, options);
      throw new DOMException('Invalid options', 'NotAllowedError');
    }

    // Abort any previous operation of the same type
    const abortController =
      type === 'create' ? this.createAbortController : this.getAbortController;

    if (abortController) {
      this.logDebug(`Aborting previous ${type} operation`);
      abortController.abort();
    }

    // Create a new AbortController for the current operation
    const newAbortController = new AbortController();
    if (type === 'create') {
      this.createAbortController = newAbortController;
    } else {
      this.getAbortController = newAbortController;
    }

    try {
      // Clean and prepare options
      const cleanedOptions = this.cleanOptions(options);
      this.logDebug(
        `Options for PublicKeyCredential${type === 'create' ? 'Creation' : 'Request'}Options`,
        cleanedOptions,
      );

      const rpId = this.getRpIdFromOptions(cleanedOptions, type);
      let accounts: Account[] | undefined;

      // If operation is 'get', fetch available credentials
      if (type === 'get') {
        accounts = await this.getAvailableCredentials(rpId);
        this.logDebug('Available accounts', accounts);
      }

      // Display the custom popup for user interaction
      const result = await window.nydiaPopup.showPopup(
        cleanedOptions,
        type,
        type === 'create' ? this.handlePasskeySave.bind(this) : this.handleGetAssertion.bind(this),
        accounts,
      );

      // Handle popup closure or errors
      if (result === 'closed') {
        this.logDebug(`Popup closed, reverting to standard WebAuthn ${type} flow`);
        return null;
      } else {
        if (result.error) {
          throw new Error(result.error);
        }
        // Process the response from the authenticator
        const credential = await WebAuthnInterceptor.processAuthenticatorResponse(result, type);
        return credential;
      }
    } catch (error: any) {
      if (error.name === 'AbortError') {
        this.logDebug(`WebAuthn ${type} operation was aborted`);
        throw error;
      } else {
        this.logDebug(`Error in WebAuthn ${type} operation`, error);
        throw error;
      }
    } finally {
      // Reset the AbortController
      if (type === 'create') {
        this.createAbortController = null;
      } else {
        this.getAbortController = null;
      }
    }
  }

  // Extracts the RP ID from the options.
  private getRpIdFromOptions(options: any, type: WebAuthnOperationType): string {
    if (type === 'create') {
      return options.publicKey.rp?.id || window.location.hostname;
    } else {
      return options.publicKey.rpId || window.location.hostname;
    }
  }

  // Cleans the options object by converting necessary fields to ArrayBuffers.
  private cleanOptions(
    options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
  ): any {
    const cleanedOptions: any = {};

    if ('publicKey' in options && options.publicKey) {
      cleanedOptions.publicKey = { ...options.publicKey };

      // Convert challenge to ArrayBuffer
      if (options.publicKey.challenge) {
        cleanedOptions.publicKey.challenge =
          typeof options.publicKey.challenge === 'string'
            ? base64UrlToArrayBuffer(options.publicKey.challenge)
            : options.publicKey.challenge;
      }

      // Convert user ID to ArrayBuffer
      if (options.publicKey.user) {
        cleanedOptions.publicKey.user = { ...options.publicKey.user };
        if (options.publicKey.user.id) {
          cleanedOptions.publicKey.user.id =
            typeof options.publicKey.user.id === 'string'
              ? base64UrlToArrayBuffer(options.publicKey.user.id)
              : options.publicKey.user.id;
        }
      }

      // Convert excludeCredentials IDs to ArrayBuffer
      if (options.publicKey.excludeCredentials) {
        cleanedOptions.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(
          (cred: any) => ({
            ...cred,
            id: typeof cred.id === 'string' ? base64UrlToArrayBuffer(cred.id) : cred.id,
          }),
        );
      }

      // Convert allowCredentials IDs to ArrayBuffer
      if (options.publicKey.allowCredentials) {
        cleanedOptions.publicKey.allowCredentials = options.publicKey.allowCredentials.map(
          (cred: any) => ({
            ...cred,
            id: typeof cred.id === 'string' ? base64UrlToArrayBuffer(cred.id) : cred.id,
          }),
        );
      }
    } else {
      // For PublicKeyCredentialRequestOptions
      if (options.challenge) {
        cleanedOptions.challenge =
          typeof options.challenge === 'string'
            ? base64UrlToArrayBuffer(options.challenge)
            : options.challenge;
      }

      if (options.allowCredentials) {
        cleanedOptions.allowCredentials = options.allowCredentials.map((cred: any) => ({
          ...cred,
          id: typeof cred.id === 'string' ? base64UrlToArrayBuffer(cred.id) : cred.id,
        }));
      }
    }

    // Copy other properties
    for (const key in options) {
      if (
        Object.prototype.hasOwnProperty.call(options, key) &&
        !['publicKey', 'challenge', 'allowCredentials', 'abortSignal', 'signal'].includes(key)
      ) {
        cleanedOptions[key] = options[key];
      }
    }

    // Add origin
    cleanedOptions.origin = window.location.origin;

    return cleanedOptions;
  }

  // Serializes options by converting ArrayBuffers to Base64 strings.
  private serializeOptions(options: any): any {
    const serializedOptions = { ...options };

    if (options.publicKey) {
      serializedOptions.publicKey = { ...options.publicKey };

      // Serialize challenge
      if (
        options.publicKey.challenge instanceof ArrayBuffer ||
        ArrayBuffer.isView(options.publicKey.challenge)
      ) {
        serializedOptions.publicKey.challenge = base64UrlEncode(options.publicKey.challenge);
      }

      // Serialize user ID
      if (options.publicKey.user) {
        serializedOptions.publicKey.user = { ...options.publicKey.user };
        const userId = options.publicKey.user.id;
        if (userId instanceof ArrayBuffer || ArrayBuffer.isView(userId)) {
          serializedOptions.publicKey.user.id = base64UrlEncode(userId);
        } else if (typeof userId === 'string') {
          serializedOptions.publicKey.user.id = userId;
        } else {
          throw new Error('publicKey.user.id must be an ArrayBuffer, TypedArray, or string');
        }
      }

      // Serialize excludeCredentials IDs
      if (options.publicKey.excludeCredentials) {
        serializedOptions.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(
          (cred: any) => ({
            ...cred,
            id: base64UrlEncode(cred.id),
          }),
        );
      }

      // Serialize allowCredentials IDs
      if (options.publicKey.allowCredentials) {
        serializedOptions.publicKey.allowCredentials = options.publicKey.allowCredentials.map(
          (cred: any) => ({
            ...cred,
            id: base64UrlEncode(cred.id),
          }),
        );
      }
    }

    // Add origin
    serializedOptions.origin = window.location.origin;

    return serializedOptions;
  }

  // Handles the passkey save operation (create).
  async handlePasskeySave(options: any): Promise<any> {
    try {
      this.logDebug('Handling passkey save operation', options);

      // Serialize options
      const serializedOptions = this.serializeOptions(options);

      // Send message to background script
      const response = await browser.runtime.sendMessage({
        type: 'createCredential',
        options: serializedOptions,
      });
      if (response.error) {
        throw new Error(response.error);
      }
      return response;
    } catch (error: any) {
      this.logDebug('Error creating passkey', error);
      throw error;
    }
  }

  // Handles the get assertion operation.
  async handleGetAssertion(options: any, selectedCredentialId?: string): Promise<any> {
    try {
      this.logDebug('Handling get assertion operation', {
        options,
        selectedCredentialId,
      });

      // Serialize options
      const serializedOptions = this.serializeOptions(options);

      // Send message to background script
      const response = await browser.runtime.sendMessage({
        type: 'handleGetAssertion',
        options: serializedOptions,
        selectedCredentialId,
      });
      if (response.error) {
        throw new Error(response.error);
      }
      return response;
    } catch (error: any) {
      this.logDebug('Error creating assertion', error);
      throw error;
    }
  }

  // Retrieves available credentials for the given RP ID.
  private async getAvailableCredentials(rpId: string): Promise<Account[]> {
    try {
      this.logDebug('Getting available credentials for rpId', rpId);
      const response = await browser.runtime.sendMessage({
        type: 'getAvailableCredentials',
        rpId,
      });
      if (response.error) {
        throw new Error(response.error);
      }
      return response as Account[];
    } catch (error: any) {
      this.logDebug('Error getting available credentials', error);
      return [];
    }
  }

  // Processes the authenticator response and constructs a Credential object.
  private static async processAuthenticatorResponse(
    parsedResponse: any,
    type: WebAuthnOperationType,
  ): Promise<Credential> {
    console.debug('[Dispatcher] Processing authenticator response:', parsedResponse);

    if (!parsedResponse.type || !parsedResponse.id || !parsedResponse.response) {
      throw new Error('Invalid response format');
    }

    // Helper to convert data to ArrayBuffer
    const toArrayBuffer = (data: any): ArrayBuffer | null => {
      if (typeof data === 'string') {
        return base64UrlToArrayBuffer(data);
      } else if (data instanceof ArrayBuffer) {
        return data;
      } else if (ArrayBuffer.isView(data)) {
        return data.buffer;
      } else if (data === null || data === undefined) {
        return null;
      } else {
        throw new Error(`Invalid data type: ${typeof data}`);
      }
    };

    const response = parsedResponse.response;

    if (type === 'create') {
      // AuthenticatorAttestationResponse
      const attestationResponse: AuthenticatorAttestationResponse = {
        clientDataJSON: toArrayBuffer(response.clientDataJSON)!,
        attestationObject: toArrayBuffer(response.attestationObject)!,
      };

      // Optional fields
      if (response.authenticatorData) {
        (attestationResponse as any).authenticatorData = toArrayBuffer(response.authenticatorData)!;
        console.debug('[Dispatcher] Added authenticatorData to attestationResponse');
      }

      if (response.publicKeyDER) {
        const publicKeyDERArrayBuffer = toArrayBuffer(response.publicKeyDER)!;
        (attestationResponse as any).getPublicKey = function () {
          return publicKeyDERArrayBuffer;
        };
        console.debug('[Dispatcher] Added getPublicKey method to attestationResponse');
      }

      if (response.publicKeyAlgorithm !== undefined) {
        const publicKeyAlgorithm = response.publicKeyAlgorithm;
        (attestationResponse as any).getPublicKeyAlgorithm = function () {
          return publicKeyAlgorithm;
        };
        console.debug('[Dispatcher] Added getPublicKeyAlgorithm method:', publicKeyAlgorithm);
      }

      const credential: PublicKeyCredential = {
        type: parsedResponse.type,
        id: parsedResponse.id,
        rawId: toArrayBuffer(parsedResponse.rawId || parsedResponse.id)!,
        response: attestationResponse,
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: parsedResponse.authenticatorAttachment || null,
      };

      console.debug('[Dispatcher] Created credential:', credential);
      return credential;
    } else {
      // AuthenticatorAssertionResponse
      const assertionResponse: AuthenticatorAssertionResponse = {
        clientDataJSON: toArrayBuffer(response.clientDataJSON)!,
        authenticatorData: toArrayBuffer(response.authenticatorData)!,
        signature: toArrayBuffer(response.signature)!,
        userHandle: response.userHandle ? toArrayBuffer(response.userHandle) : null,
      };

      const credential: PublicKeyCredential = {
        type: parsedResponse.type,
        id: parsedResponse.id,
        rawId: toArrayBuffer(parsedResponse.rawId || parsedResponse.id)!,
        response: assertionResponse,
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: parsedResponse.authenticatorAttachment || null,
      };

      return credential;
    }
  }

  // Logs debug messages with consistent formatting.
  private logDebug(message: string, data?: any): void {
    if (data !== undefined) {
      console.debug(`[WebAuthnInterceptor] ${message}:`, data);
    } else {
      console.debug(`[WebAuthnInterceptor] ${message}`);
    }
  }
}

// Initialize the interceptor
const interceptor = new WebAuthnInterceptor();

// Listens for messages from the injector.js script and handles them.
window.addEventListener('message', async (event) => {
  // Ensure the message is from the same window and origin
  if (event.source !== window || event.origin !== window.location.origin) {
    return;
  }

  const message = event.data;

  if (message && message.type === 'webauthn-create') {
    // Handle navigator.credentials.create()
    try {
      if (
        (await interceptor.shouldIntercept()) &&
        message.options &&
        typeof message.options === 'object'
      ) {
        const credential = await interceptor.interceptCreate(message.options);
        if (credential === null) {
          window.postMessage({ type: 'webauthn-create-fallback' }, '*');
        } else {
          const response = {
            type: credential.type,
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            response: {
              clientDataJSON: base64UrlEncode(
                (credential.response as AuthenticatorAttestationResponse).clientDataJSON,
              ),
              attestationObject: base64UrlEncode(
                (credential.response as AuthenticatorAttestationResponse).attestationObject,
              ),
              ...((credential.response as any).authenticatorData && {
                authenticatorData: base64UrlEncode((credential.response as any).authenticatorData),
              }),
              ...((credential.response as any).getPublicKey && {
                publicKeyDER: base64UrlEncode((credential.response as any).getPublicKey()),
              }),
              ...((credential.response as any).getPublicKeyAlgorithm && {
                publicKeyAlgorithm: (credential.response as any).getPublicKeyAlgorithm(),
              }),
            },
            authenticatorAttachment: credential.authenticatorAttachment,
          };

          console.debug('[Dispatcher] Sending response to injector.js:', response);

          window.postMessage({ type: 'webauthn-create-response', response }, '*');
        }
      } else {
        window.postMessage({ type: 'webauthn-create-fallback' }, '*');
      }
    } catch (error: any) {
      interceptor.logDebug('Error handling WebAuthn create', error);
      window.postMessage({ type: 'webauthn-create-error', error: error.message }, '*');
    }
  } else if (message && message.type === 'webauthn-get') {
    // Handle navigator.credentials.get()
    try {
      if (
        (await interceptor.shouldIntercept()) &&
        message.options &&
        typeof message.options === 'object'
      ) {
        const credential = await interceptor.interceptGet(message.options);
        if (credential === null) {
          window.postMessage({ type: 'webauthn-get-fallback' }, '*');
        } else {
          const response = {
            type: credential.type,
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            response: {
              clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
              authenticatorData: base64UrlEncode(
                (credential.response as AuthenticatorAssertionResponse).authenticatorData,
              ),
              signature: base64UrlEncode(
                (credential.response as AuthenticatorAssertionResponse).signature,
              ),
              userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle
                ? base64UrlEncode(
                    (credential.response as AuthenticatorAssertionResponse).userHandle!,
                  )
                : null,
            },
            authenticatorAttachment: credential.authenticatorAttachment,
          };

          window.postMessage({ type: 'webauthn-get-response', response }, '*');
        }
      } else {
        window.postMessage({ type: 'webauthn-get-fallback' }, '*');
      }
    } catch (error: any) {
      interceptor.logDebug('Error handling WebAuthn get', error);
      window.postMessage({ type: 'webauthn-get-error', error: error.message }, '*');
    }
  }
});

console.log('WebAuthn content script fully initialized');
