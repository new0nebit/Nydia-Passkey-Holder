import browser from 'browser-api';

import { logDebug } from './logger';
import { serializeError, toDomException } from './utils/domError';
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

// Rebuild the error a background handler reported. DOMExceptions keep their
// (whitelisted) name so the RP ultimately sees the spec error; everything else
// stays a plain Error — internal signals like `rootKeyMissing` rely on the
// message being matched verbatim.
function rebuildBackgroundError(response: { error?: string; errorName?: string }): Error {
  return response.errorName !== undefined
    ? toDomException(response.error, response.errorName)
    : new Error(response.error);
}

const isTopFrame = (() => {
  try {
    return window.self === window.top;
  } catch {
    return false;
  }
})();

// Class responsible for intercepting and handling WebAuthn operations.
class WebAuthnInterceptor {
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

    try {
      logDebug(
        `[Dispatcher] Options for PublicKeyCredential${type === 'create' ? 'Creation' : 'Request'}Options`,
        options,
      );

      const rpId = this.getRpIdFromOptions(options, type);
      if (type === 'create') {
        const response = (await browser.runtime.sendMessage({
          type: 'validateRpId',
          rpId,
        })) as { valid?: boolean; error?: string; errorName?: string };

        if (response?.error) {
          throw rebuildBackgroundError(response);
        }
        if (!response?.valid) {
          throw new Error('Unable to validate rpId');
        }
      }

      let accounts: Account[] | undefined;

      // If operation is 'get', fetch available credentials
      if (type === 'get') {
        const requestOptions = options;
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
          ? (options as CreationOptions).publicKey.user.name
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
          ? this.handlePasskeySave(options as CreationOptions)
          : this.handleGetAssertion(options, selectedUniqueId);
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
      if (type === 'get' && error instanceof Error && error.message === 'rootKeyMissing') {
        logDebug('[Dispatcher] rootKey unavailable, falling back to native browser');
        return null;
      }
      logDebug(`[Dispatcher] WebAuthn ${type} operation failed`, error);
      throw error;
    }
  }

  // Extracts the RP ID from the options.
  private getRpIdFromOptions(
    options: CreationOptions | RequestOptions,
    type: WebAuthnOperationType,
  ): string {
    if (type === 'create') {
      const requestedRpId = (options as CreationOptions).publicKey.rp?.id;
      return requestedRpId === undefined ? window.location.hostname : requestedRpId;
    }
    const requestedRpId =
      'rpId' in options.publicKey ? options.publicKey.rpId : undefined;
    return requestedRpId === undefined ? window.location.hostname : requestedRpId;
  }

  async handlePasskeySave(options: CreationOptions): Promise<unknown> {
    logDebug('[Dispatcher] Handling passkey save operation', options);
    const response = (await browser.runtime.sendMessage({
      type: 'createCredential',
      options,
    })) as { error?: string; errorName?: string };
    if (response.error) {
      throw rebuildBackgroundError(response);
    }
    return response;
  }

  async handleGetAssertion(options: RequestOptions, selectedUniqueId?: string): Promise<unknown> {
    logDebug('[Dispatcher] Handling get assertion operation', { options, selectedUniqueId });
    const response = (await browser.runtime.sendMessage({
      type: 'handleGetAssertion',
      options,
      selectedUniqueId,
    })) as { error?: string; errorName?: string };
    if (response.error) {
      throw rebuildBackgroundError(response);
    }
    return response;
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
      })) as Account[] | { error?: string; errorName?: string };
      if (Array.isArray(response)) return response;
      if (response?.error) {
        throw rebuildBackgroundError(response);
      }
      return [];
    } catch (error: unknown) {
      if (error instanceof Error && error.message === 'rootKeyMissing') throw error;
      if (error instanceof DOMException && error.name === 'SecurityError') throw error;
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

  type Handler = (options: CreationOptions | RequestOptions) => Promise<SerializedWebAuthnResponse | null>;

  const messageHandlers = new Map<string, Handler>([
    ['webauthn-create', (options) => interceptor.interceptCreate(options as CreationOptions)],
    ['webauthn-get', (options) => interceptor.interceptGet(options)],
  ]);

  // Listens for messages from the injector.js script and handles them.
  window.addEventListener('message', (event) => {
    void (async () => {
      if (event.source !== window || event.origin !== window.location.origin) {
        return;
      }

      const message = event.data as { type?: string; options?: unknown };
      if (!message?.type) return;

      const handler = messageHandlers.get(message.type);
      if (!handler) return;

      const messageType = message.type;

      try {
        if (!message.options || typeof message.options !== 'object') {
          window.postMessage({ type: `${messageType}-fallback` }, '*');
          return;
        }

        const response = await handler(message.options as CreationOptions | RequestOptions);

        if (response === null) {
          window.postMessage({ type: `${messageType}-fallback` }, '*');
        } else {
          window.postMessage({ type: `${messageType}-response`, response }, '*');
        }
      } catch (error: unknown) {
        const { message: messageText, name: errorName } = serializeError(error);
        logDebug(`[Dispatcher] Error handling ${messageType}`, error);
        window.postMessage(
          { type: `${messageType}-error`, error: messageText, errorName },
          '*',
        );
      }
    })();
  });

  logDebug('[Dispatcher] WebAuthn content script fully initialized');
}

if (!isTopFrame) {
  logDebug('[Dispatcher] Iframe detected; skipping WebAuthn injection');
} else if (!window.isSecureContext) {
  // Leave WebAuthn untouched when the browser reports an insecure context.
  // Background independently validates the sender origin.
  logDebug('[Dispatcher] Insecure context; skipping WebAuthn injection');
} else {
  initDispatcher();
}
