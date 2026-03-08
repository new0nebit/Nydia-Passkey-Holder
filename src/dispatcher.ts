import browser from 'browser-api';

import { logDebug } from './logger';
import { showPopup } from './popup/shadowHost';
import { PopupInitPayload } from './popup/messages';
import {
  Account,
  AssertionResponse,
  AttestationResponse,
  SerializedCreationOptions,
  SerializedRequestOptions,
  WebAuthnOperationType,
} from './types';

type CreationOptions = SerializedCreationOptions;
type RequestOptions = SerializedRequestOptions;
type SerializedWebAuthnResponse = AttestationResponse | AssertionResponse;

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
  async interceptCreate(options: CreationOptions): Promise<SerializedWebAuthnResponse | null> {
    return this.interceptWebAuthn(options, 'create');
  }

  // Intercepts navigator.credentials.get() calls.
  async interceptGet(options: RequestOptions): Promise<SerializedWebAuthnResponse | null> {
    return this.interceptWebAuthn(options, 'get');
  }

  // General method to intercept WebAuthn operations.
  private async interceptWebAuthn(
    options: CreationOptions | RequestOptions,
    type: WebAuthnOperationType,
  ): Promise<SerializedWebAuthnResponse | null> {
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
      const normalizedOptions = this.withOrigin(options);
      logDebug(
        `[Dispatcher] Options for PublicKeyCredential${type === 'create' ? 'Creation' : 'Request'}Options`,
        normalizedOptions,
      );

      const rpId = this.getRpIdFromOptions(normalizedOptions, type);
      let accounts: Account[] | undefined;

      // If operation is 'get', fetch available credentials
      if (type === 'get') {
        const requestOptions = normalizedOptions as RequestOptions;
        const allowCredentialIds = this.getAllowCredentialIds(requestOptions);
        accounts = await this.getAvailableCredentials(rpId, allowCredentialIds);
        logDebug('[Dispatcher] Available accounts', accounts.map((account) => ({
          uniqueId: account.uniqueId,
          username: account.username,
          creationTime: new Date(account.creationTime ?? 0).toISOString().slice(0, 19).replace('T', ' ').replaceAll('-', '/'),
        })));

        // If no passkeys available for this rpId, fallback to native browser
        if (!accounts || accounts.length === 0) {
          logDebug('[Dispatcher] No passkeys found, falling back to native browser');
          return null;
        }
      }

      const userName =
        type === 'create'
          ? (normalizedOptions as CreationOptions).publicKey.user.name
          : '';

      const payload: PopupInitPayload = {
        operationType: type,
        rpId,
        userName,
        accounts,
      };

      // Display the custom popup for user interaction
      const onAction = (selectedUniqueId?: string): Promise<unknown> => {
        return type === 'create'
          ? this.handlePasskeySave(normalizedOptions as CreationOptions)
          : this.handleGetAssertion(normalizedOptions as RequestOptions, selectedUniqueId);
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

      return result as SerializedWebAuthnResponse;
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

  private withOrigin<T extends CreationOptions | RequestOptions>(options: T): T {
    return {
      ...options,
      origin: window.location.origin,
    };
  }

  // Extracts the RP ID from the options.
  private getRpIdFromOptions(
    options: CreationOptions | RequestOptions,
    type: WebAuthnOperationType,
  ): string {
    if (type === 'create') {
      return (options as CreationOptions).publicKey.rp?.id || window.location.hostname;
    }
    return (options as RequestOptions).publicKey.rpId || window.location.hostname;
  }

  // Handles the passkey save operation (create).
  async handlePasskeySave(options: CreationOptions): Promise<unknown> {
    try {
      logDebug('[Dispatcher] Handling passkey save operation', options);

      // Send message to background script
      const response = (await browser.runtime.sendMessage({
        type: 'createCredential',
        options,
      })) as { error?: string };
      if (response.error) {
        throw new Error(response.error);
      }
      return response;
    } catch (error: unknown) {
      logDebug('[Dispatcher] Error creating passkey', error instanceof Error ? error.message : error);
      throw error;
    }
  }

  // Handles the get assertion operation.
  async handleGetAssertion(options: RequestOptions, selectedUniqueId?: string): Promise<unknown> {
    try {
      logDebug('[Dispatcher] Handling get assertion operation', {
        options,
        selectedUniqueId,
      });

      // Send message to background script
      const response = (await browser.runtime.sendMessage({
        type: 'handleGetAssertion',
        options,
        selectedUniqueId,
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

  private getAllowCredentialIds(options: RequestOptions): string[] | undefined {
    const descriptors = options.publicKey.allowCredentials;
    if (!Array.isArray(descriptors) || descriptors.length === 0) {
      return undefined;
    }

    return descriptors.map((descriptor) => descriptor.id);
  }

  // Retrieves available credentials for the given RP ID.
  private async getAvailableCredentials(
    rpId: string,
    allowCredentialIds?: string[],
  ): Promise<Account[]> {
    try {
      logDebug('[Dispatcher] Getting available credentials for rpId', rpId);
      const response = (await browser.runtime.sendMessage({
        type: 'getAvailableCredentials',
        rpId,
        allowCredentialIds,
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
  window.addEventListener('message', (event) => {
    void (async () => {
      // Ensure the message is from the same window and origin
      if (event.source !== window || event.origin !== window.location.origin) {
        return;
      }

      const message = event.data as { type?: string; options?: unknown; selectedUniqueId?: string };

      if (message && message.type === 'webauthn-create') {
        // Handle navigator.credentials.create()
        try {
          if (message.options && typeof message.options === 'object') {
            const creationOptions = message.options as CreationOptions;
            const response = await interceptor.interceptCreate(creationOptions);
            if (response === null) {
              window.postMessage({ type: 'webauthn-create-fallback' }, '*');
            } else {
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
            const requestOptions = message.options as RequestOptions;
            const response = await interceptor.interceptGet(requestOptions);
            if (response === null) {
              window.postMessage({ type: 'webauthn-get-fallback' }, '*');
            } else {
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
    })();
  });

  logDebug('[Dispatcher] WebAuthn content script fully initialized');
}

if (!isTopFrame) {
  logDebug('[Dispatcher] Iframe detected; skipping WebAuthn injection');
} else {
  initDispatcher();
}
