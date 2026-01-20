import browser from 'browser-api';

import { logDebug } from './logger';
import { showPopup } from './popup/shadowHost';
import { PopupInitPayload } from './popup/messages';
import { Account, WebAuthnOperationType } from './types';
import { toArrayBuffer } from './utils/buffer';
import { base64UrlEncode } from './utils/base64url';

type CreationOptions = CredentialCreationOptions & {
  publicKey: PublicKeyCredentialCreationOptions;
};

type RequestOptions = CredentialRequestOptions & {
  publicKey: PublicKeyCredentialRequestOptions;
};

type CleanedOptions = CreationOptions | RequestOptions;

const isTopFrame = (() => {
  try {
    return window.self === window.top;
  } catch {
    return false;
  }
})();

// Class responsible for intercepting and handling WebAuthn operations.
class WebAuthnInterceptor {
  private createAbortController: AbortController | null = null;
  private getAbortController: AbortController | null = null;

  // Intercepts navigator.credentials.create() calls.
  async interceptCreate(options: CreationOptions): Promise<PublicKeyCredential | null> {
    return this.interceptWebAuthn(options, 'create');
  }

  // Intercepts navigator.credentials.get() calls.
  async interceptGet(options: RequestOptions): Promise<PublicKeyCredential | null> {
    return this.interceptWebAuthn(options, 'get');
  }

  // General method to intercept WebAuthn operations.
  private async interceptWebAuthn(
    options: CreationOptions | RequestOptions,
    type: WebAuthnOperationType,
  ): Promise<PublicKeyCredential | null> {
    logDebug(`[Dispatcher] Intercepting WebAuthn operation: ${type}`);

    if (!options || typeof options !== 'object') {
      logDebug(`[Dispatcher] Invalid options for ${type}`, options);
      throw new DOMException('Invalid options', 'NotAllowedError');
    }

    // Abort any previous operation of the same type
    const abortController =
      type === 'create' ? this.createAbortController : this.getAbortController;

    if (abortController) {
      logDebug(`[Dispatcher] Aborting previous ${type} operation`);
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
      logDebug(
        `[Dispatcher] Options for PublicKeyCredential${type === 'create' ? 'Creation' : 'Request'}Options`,
        cleanedOptions,
      );

      const rpId = this.getRpIdFromOptions(cleanedOptions, type);
      let accounts: Account[] | undefined;

      // If operation is 'get', fetch available credentials
      if (type === 'get') {
        accounts = await this.getAvailableCredentials(rpId);
        logDebug('[Dispatcher] Available accounts', accounts);

        // If no passkeys available for this rpId, fallback to native browser
        if (!accounts || accounts.length === 0) {
          logDebug('[Dispatcher] No passkeys found, falling back to native browser');
          return null;
        }
      }

      const userName =
        type === 'create' && this.isCreateOptions(cleanedOptions) && cleanedOptions.publicKey.user
          ? cleanedOptions.publicKey.user.name
          : '';

      const payload: PopupInitPayload = {
        operationType: type,
        rpId,
        userName,
        accounts,
      };

      // Display the custom popup for user interaction
      const onAction = (selectedCredentialId?: string): Promise<unknown> => {
        return type === 'create'
          ? this.handlePasskeySave(cleanedOptions as CreationOptions)
          : this.handleGetAssertion(cleanedOptions as RequestOptions, selectedCredentialId);
      };

      const result = await showPopup(payload, onAction);

      // Handle popup closure or errors
      if (result === 'closed') {
        logDebug(`[Dispatcher] Popup closed, reverting to standard WebAuthn ${type} flow`);
        return null;
      }

      if (
        !result ||
        typeof result !== 'object' ||
        !('response' in (result as Record<string, unknown>))
      ) {
        throw new Error('Invalid response from popup');
      }

      // Process the response from the authenticator
      const credential = await WebAuthnInterceptor.processAuthenticatorResponse(
        result as Record<string, unknown>,
        type,
      );
      return credential;
    } catch (error: unknown) {
      const isAbort = error instanceof DOMException && error.name === 'AbortError';
      logDebug(`[Dispatcher] WebAuthn ${type} operation ${isAbort ? 'was aborted' : 'failed'}`, error);
      throw error;
    } finally {
      // Reset the AbortController
      if (type === 'create') {
        this.createAbortController = null;
      } else {
        this.getAbortController = null;
      }
    }
  }

  private isCreateOptions(options: CreationOptions | RequestOptions): options is CreationOptions {
    return 'user' in options.publicKey;
  }

  // Extracts the RP ID from the options.
  private getRpIdFromOptions(
    options: CreationOptions | RequestOptions,
    type: WebAuthnOperationType,
  ): string {
    if (type === 'create' && this.isCreateOptions(options)) {
      return options.publicKey.rp?.id || window.location.hostname;
    }
    return (options as RequestOptions).publicKey.rpId || window.location.hostname;
  }

  // Cleans the options object by converting necessary fields to ArrayBuffers.
  private cleanOptions(options: CreationOptions | RequestOptions): CleanedOptions {
    if (this.isCreateOptions(options)) {
      const publicKey: PublicKeyCredentialCreationOptions = { ...options.publicKey };

      publicKey.challenge = toArrayBuffer(options.publicKey.challenge as ArrayBuffer | Uint8Array);

      publicKey.user = { ...options.publicKey.user };
      publicKey.user.id = toArrayBuffer(options.publicKey.user.id as ArrayBuffer | Uint8Array);

      if (options.publicKey.excludeCredentials) {
        publicKey.excludeCredentials = options.publicKey.excludeCredentials.map((descriptor) => ({
          ...descriptor,
          id: toArrayBuffer(descriptor.id as ArrayBuffer | Uint8Array),
        }));
      }

      return {
        ...options,
        publicKey,
        origin: window.location.origin,
      } as CreationOptions;
    }

    const publicKey: PublicKeyCredentialRequestOptions = { ...options.publicKey };

    publicKey.challenge = toArrayBuffer(options.publicKey.challenge as ArrayBuffer | Uint8Array);

    if (options.publicKey.allowCredentials) {
      publicKey.allowCredentials = options.publicKey.allowCredentials.map((descriptor) => ({
        ...descriptor,
        id: toArrayBuffer(descriptor.id as ArrayBuffer | Uint8Array),
      }));
    }

    return {
      ...options,
      publicKey,
      origin: window.location.origin,
    } as RequestOptions;
  }

  // Serializes options by converting ArrayBuffers/Uint8Arrays to base64url strings.
  private serializeOptions(
    options: CreationOptions | RequestOptions,
  ): Record<string, unknown> {
    const serializedOptions: Record<string, unknown> = { ...options };

    if (options.publicKey) {
      const publicKey: Record<string, unknown> = { ...options.publicKey };
      serializedOptions.publicKey = publicKey;

      // Serialize challenge
      const pkChallenge = options.publicKey.challenge;
      if (pkChallenge instanceof ArrayBuffer || pkChallenge instanceof Uint8Array) {
        publicKey.challenge = base64UrlEncode(pkChallenge);
      }

      // Serialize user ID
      if (this.isCreateOptions(options) && options.publicKey.user) {
        const user: Record<string, unknown> = { ...options.publicKey.user };
        const userId = options.publicKey.user.id;
        if (userId instanceof ArrayBuffer || userId instanceof Uint8Array) {
          user.id = base64UrlEncode(userId);
        } else if (typeof userId === 'string') {
          user.id = userId;
        } else {
          throw new Error('publicKey.user.id must be an ArrayBuffer, Uint8Array, or string');
        }
        publicKey.user = user;
      }

      // Serialize excludeCredentials IDs
      if (this.isCreateOptions(options) && options.publicKey.excludeCredentials) {
        publicKey.excludeCredentials = options.publicKey.excludeCredentials.map((descriptor) => ({
          ...descriptor,
          id: base64UrlEncode(descriptor.id as ArrayBuffer | Uint8Array),
        }));
      }

      // Serialize allowCredentials IDs
      if (!this.isCreateOptions(options) && options.publicKey.allowCredentials) {
        publicKey.allowCredentials = options.publicKey.allowCredentials.map((descriptor: PublicKeyCredentialDescriptor) => ({
          ...descriptor,
          id: base64UrlEncode(descriptor.id as ArrayBuffer | Uint8Array),
        }));
      }
    }

    // Add origin
    serializedOptions.origin = window.location.origin;

    return serializedOptions;
  }

  // Handles the passkey save operation (create).
  async handlePasskeySave(options: CreationOptions): Promise<unknown> {
    try {
      logDebug('[Dispatcher] Handling passkey save operation', options);

      // Serialize options
      const serializedOptions = this.serializeOptions(options);

      // Send message to background script
      const response = (await browser.runtime.sendMessage({
        type: 'createCredential',
        options: serializedOptions,
      })) as { error?: string };
      if (response.error) {
        throw new Error(response.error);
      }
      return response;
    } catch (error: unknown) {
      logDebug('[Dispatcher] Error creating passkey', error);
      throw error;
    }
  }

  // Handles the get assertion operation.
  async handleGetAssertion(options: RequestOptions, selectedCredentialId?: string): Promise<unknown> {
    try {
      logDebug('[Dispatcher] Handling get assertion operation', {
        options,
        selectedCredentialId,
      });

      // Serialize options
      const serializedOptions = this.serializeOptions(options);

      // Send message to background script
      const response = (await browser.runtime.sendMessage({
        type: 'handleGetAssertion',
        options: serializedOptions,
        selectedCredentialId,
      })) as { error?: string };
      if (response.error) {
        throw new Error(response.error);
      }
      return response;
    } catch (error: unknown) {
      logDebug('[Dispatcher] Error creating assertion', error);
      throw error;
    }
  }

  // Retrieves available credentials for the given RP ID.
  private async getAvailableCredentials(rpId: string): Promise<Account[]> {
    try {
      logDebug('[Dispatcher] Getting available credentials for rpId', rpId);
      const response = (await browser.runtime.sendMessage({
        type: 'getAvailableCredentials',
        rpId,
      })) as Account[] | { error?: string };
      if (Array.isArray(response)) return response;
      if (response?.error) {
        throw new Error(response.error);
      }
      return [];
    } catch (error: unknown) {
      logDebug('[Dispatcher] Error getting available credentials', error);
      return [];
    }
  }

  // Processes the authenticator response and constructs a Credential object.
  private static async processAuthenticatorResponse(
    parsedResponse: Record<string, unknown>,
    type: WebAuthnOperationType,
  ): Promise<PublicKeyCredential> {
    logDebug('[Dispatcher] Processing authenticator response', parsedResponse);

    if (!parsedResponse.type || !parsedResponse.id || !parsedResponse.response) {
      throw new Error('Invalid response format');
    }

    const response = parsedResponse.response as Record<string, unknown>;

    if (type === 'create') {
      // AuthenticatorAttestationResponse
      const attestationResponse = {
        clientDataJSON: toArrayBuffer(response.clientDataJSON as string),
        attestationObject: toArrayBuffer(response.attestationObject as string),
        getAuthenticatorData: response.authenticatorData
          ? () => toArrayBuffer(response.authenticatorData as string)
          : undefined,
        getPublicKey: response.publicKeyDER
          ? () => toArrayBuffer(response.publicKeyDER as string)
          : undefined,
        getPublicKeyAlgorithm:
          response.publicKeyAlgorithm !== undefined
            ? () => response.publicKeyAlgorithm as number
            : undefined,
        getTransports: () => ['internal'],
      } as AuthenticatorAttestationResponse;

      return {
        type: parsedResponse.type as Credential['type'],
        id: parsedResponse.id as string,
        rawId: toArrayBuffer((parsedResponse.rawId || parsedResponse.id) as string),
        response: attestationResponse,
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: 'platform',
        toJSON: () => parsedResponse,
      } as PublicKeyCredential;
    }

    // AuthenticatorAssertionResponse
    const assertionResponse = {
      clientDataJSON: toArrayBuffer(response.clientDataJSON as string),
      authenticatorData: toArrayBuffer(response.authenticatorData as string),
      signature: toArrayBuffer(response.signature as string),
      userHandle: response.userHandle === null || response.userHandle === undefined
        ? null
        : toArrayBuffer(response.userHandle as string),
      getTransports: () => ['internal'],
    } as AuthenticatorAssertionResponse;

    return {
      type: parsedResponse.type as Credential['type'],
      id: parsedResponse.id as string,
      rawId: toArrayBuffer((parsedResponse.rawId || parsedResponse.id) as string),
      response: assertionResponse,
      getClientExtensionResults: () => ({}),
      authenticatorAttachment: 'platform',
      toJSON: () => parsedResponse,
    } as PublicKeyCredential;
  }

}

function initDispatcher(): void {
  // Inject the injector.js script into the page to override WebAuthn methods.
  const script = document.createElement('script');
  script.src = browser.runtime.getURL('injector.js');
  (document.head || document.documentElement).appendChild(script);
  script.onload = () => {
    script.remove();
  };

  // Initialize the interceptor
  const interceptor = new WebAuthnInterceptor();

  // Listens for messages from the injector.js script and handles them.
  window.addEventListener('message', async (event) => {
    // Ensure the message is from the same window and origin
    if (event.source !== window || event.origin !== window.location.origin) {
      return;
    }

    const message = event.data as { type?: string; options?: unknown; selectedCredentialId?: string };

    if (message && message.type === 'webauthn-create') {
      // Handle navigator.credentials.create()
      try {
        if (message.options && typeof message.options === 'object') {
          const opts = message.options as CreationOptions;
          const credential = await interceptor.interceptCreate(opts);
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
                ...(() => {
                  const att = credential.response as AuthenticatorAttestationResponse & {
                    getAuthenticatorData?: () => ArrayBuffer;
                    getPublicKey?: () => ArrayBuffer;
                    getPublicKeyAlgorithm?: () => number;
                  };
                  const extras: Record<string, unknown> = {};
                  const authData = att.getAuthenticatorData?.();
                  if (authData) extras.authenticatorData = base64UrlEncode(authData);
                  const publicKeyDer = att.getPublicKey?.();
                  if (publicKeyDer) extras.publicKeyDER = base64UrlEncode(publicKeyDer);
                  const alg = att.getPublicKeyAlgorithm?.();
                  if (alg !== undefined) extras.publicKeyAlgorithm = alg;
                  return extras;
                })(),
              },
              authenticatorAttachment: credential.authenticatorAttachment,
            };

            window.postMessage({ type: 'webauthn-create-response', response }, '*');
          }
        } else {
          window.postMessage({ type: 'webauthn-create-fallback' }, '*');
        }
      } catch (error: unknown) {
        const messageText = error instanceof Error ? error.message : String(error);
        logDebug('[Dispatcher] Error handling WebAuthn create', error);
        window.postMessage({ type: 'webauthn-create-error', error: messageText }, '*');
      }
    } else if (message && message.type === 'webauthn-get') {
      // Handle navigator.credentials.get()
      try {
        if (message.options && typeof message.options === 'object') {
          const opts = message.options as RequestOptions;
          const credential = await interceptor.interceptGet(opts);
          if (credential === null) {
            window.postMessage({ type: 'webauthn-get-fallback' }, '*');
          } else {
            const assertionResp = credential.response as AuthenticatorAssertionResponse;
            const response = {
              type: credential.type,
              id: credential.id,
              rawId: base64UrlEncode(credential.rawId),
              response: {
                clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
                authenticatorData: base64UrlEncode(assertionResp.authenticatorData),
                signature: base64UrlEncode(assertionResp.signature),
                userHandle: assertionResp.userHandle ? base64UrlEncode(assertionResp.userHandle) : null,
              },
              authenticatorAttachment: credential.authenticatorAttachment,
            };

            window.postMessage({ type: 'webauthn-get-response', response }, '*');
          }
        } else {
          window.postMessage({ type: 'webauthn-get-fallback' }, '*');
        }
      } catch (error: unknown) {
        const messageText = error instanceof Error ? error.message : String(error);
        logDebug('[Dispatcher] Error handling WebAuthn get', error);
        window.postMessage({ type: 'webauthn-get-error', error: messageText }, '*');
      }
    }
  });

  logDebug('[Dispatcher] WebAuthn content script fully initialized');
}

if (!isTopFrame) {
  logDebug('[Dispatcher] Iframe detected; skipping WebAuthn injection');
} else {
  initDispatcher();
}
