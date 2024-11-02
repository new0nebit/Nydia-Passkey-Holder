import { createCredential, handleGetAssertion } from './authenticator';
import { base64UrlEncode, getUserNameFromOptions } from './store';
import { WebAuthnPopup, PopupOptions, WebAuthnOperationType } from './popup';

function logInfo(message: string, data?: any) {
  console.log(`[WebAuthn] ${message}`, data !== undefined ? data : '');
}

function logError(message: string, error?: any) {
  console.error(`[WebAuthn Error] ${message}`, error);
}

(() => {
  logInfo('WebAuthn interception script initialized');

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  class WebAuthnInterceptor {
    private interceptEnabled = true;
    private createAbortController: AbortController | null = null;
    private getAbortController: AbortController | null = null;

    async shouldIntercept(type: WebAuthnOperationType): Promise<boolean> {
      return this.interceptEnabled;
    }

    async interceptCreate(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential | null> {
      return this.interceptWebAuthn(options, 'create');
    }

    async interceptGet(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential | null> {
      return this.interceptWebAuthn(options, 'get');
    }

    private async interceptWebAuthn(
      options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
      type: WebAuthnOperationType
    ): Promise<PublicKeyCredential | null> {
      logInfo(`Intercepting WebAuthn ${type} operation`);

      if (!options || typeof options !== 'object') {
        logError(`Invalid options provided for ${type}`);
        throw new DOMException("Invalid options", "NotAllowedError");
      }

      const abortController = type === 'create' ? this.createAbortController : this.getAbortController;

      if (abortController) {
        logInfo(`Aborting previous ${type} operation`);
        abortController.abort();
      }

      const newAbortController = new AbortController();
      if (type === 'create') {
        this.createAbortController = newAbortController;
      } else {
        this.getAbortController = newAbortController;
      }

      try {
        const cleanedOptions = this.cleanOptions(options, window.location.origin);
        const encodedOptions = btoa(JSON.stringify(cleanedOptions));
        logInfo(`Encoded PublicKeyCredential${type === 'create' ? 'Creation' : 'Request'}Options`, encodedOptions);

        let userName: string | undefined;

        if (type === 'get') {
          userName = await getUserNameFromOptions(options as PublicKeyCredentialRequestOptions);
        } else if (type === 'create' && 'user' in options && options.user) {
          userName = options.user.displayName;
        }

        const result = await this.showPopup(encodedOptions, type, newAbortController.signal, userName);

        if (result === 'closed') {
          logInfo(`Popup closed, falling back to native WebAuthn ${type} flow`);
          return null;
        } else {
          const parsedResult = JSON.parse(result);
          const credential = WebAuthnInterceptor.processAuthenticatorResponse(parsedResult, type);
          return credential;
        }
      } catch (error: any) {
        if (error.name === 'AbortError') {
          logInfo(`WebAuthn ${type} operation aborted`);
          throw error;
        } else {
          logError(`Error in WebAuthn ${type} operation`, error);
          throw error;
        }
      } finally {
        if (type === 'create') {
          this.createAbortController = null;
        } else {
          this.getAbortController = null;
        }
      }
    }

    private cleanOptions(
      options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
      origin: string
    ): any {
      const cleanedOptions: any = {
        publicKey: {},
        origin,
        rpId: ('rp' in options && options.rp && options.rp.id) ? options.rp.id : new URL(origin).hostname,
      };

      if ('rp' in options) cleanedOptions.publicKey.rp = options.rp;
      if ('user' in options && options.user) {
        cleanedOptions.publicKey.user = {
          ...options.user,
          id: this.bufferSourceToBase64(options.user.id),
        };
      }
      if ('challenge' in options) {
        cleanedOptions.publicKey.challenge = this.bufferSourceToBase64(options.challenge);
      }
      if ('pubKeyCredParams' in options) cleanedOptions.publicKey.pubKeyCredParams = options.pubKeyCredParams;
      if ('timeout' in options) cleanedOptions.publicKey.timeout = options.timeout;
      if ('excludeCredentials' in options) {
        cleanedOptions.publicKey.excludeCredentials = options.excludeCredentials?.map(cred => ({
          ...cred,
          id: this.bufferSourceToBase64(cred.id),
        }));
      }
      if ('authenticatorSelection' in options) cleanedOptions.publicKey.authenticatorSelection = options.authenticatorSelection;
      if ('attestation' in options) cleanedOptions.publicKey.attestation = options.attestation;
      if ('extensions' in options) cleanedOptions.publicKey.extensions = options.extensions;
      if ('allowCredentials' in options) {
        cleanedOptions.publicKey.allowCredentials = options.allowCredentials?.map(cred => ({
          ...cred,
          id: this.bufferSourceToBase64(cred.id),
        }));
      }

      return cleanedOptions;
    }

    private bufferSourceToBase64(buffer: BufferSource): string {
      const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    private static processAuthenticatorResponse(parsedResponse: any, type: WebAuthnOperationType): PublicKeyCredential {
      if (!parsedResponse.type || !parsedResponse.id || !parsedResponse.response) {
        throw new Error('Invalid response format');
      }

      const credential: PublicKeyCredential = {
        type: parsedResponse.type,
        id: parsedResponse.id,
        rawId: WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.rawId || parsedResponse.id),
        response: type === 'create'
          ? {
              clientDataJSON: WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.response.clientDataJSON),
              attestationObject: WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.response.attestationObject),
            } as AuthenticatorAttestationResponse
          : {
              clientDataJSON: WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.response.clientDataJSON),
              authenticatorData: WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.response.authenticatorData),
              signature: WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.response.signature),
              userHandle: parsedResponse.response.userHandle ? WebAuthnInterceptor.base64ToArrayBuffer(parsedResponse.response.userHandle) : null,
            } as AuthenticatorAssertionResponse,
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: 'platform',
      };

      return credential;
    }

    private static base64ToArrayBuffer(base64: string): ArrayBuffer {
      const binaryString = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    }

    private async handlePasskeySave(encodedOptions: string): Promise<string> {
      try {
        logInfo('Handling passkey save operation');
        const options = JSON.parse(atob(encodedOptions));
        logInfo('Decoded options', options);

        const attestationResponse = await createCredential({
          ...options.publicKey,
          origin: options.origin,
          rpId: options.rpId,
        });

        if (attestationResponse) {
          logInfo('Passkey successfully created');
          return JSON.stringify(attestationResponse);
        } else {
          logInfo('Passkey creation failed');
          return JSON.stringify({ error: 'Passkey creation failed' });
        }
      } catch (error) {
        logError('Error creating passkey', error);
        throw error;
      }
    }

    private async handleGetAssertion(encodedOptions: string): Promise<string> {
      try {
        logInfo('Handling get assertion operation');
        const options = JSON.parse(atob(encodedOptions));
        logInfo('Decoded options', options);

        const assertionResponse = await handleGetAssertion(options);

        if (assertionResponse) {
          logInfo('Assertion successfully created');

          const base64Response = {
            type: assertionResponse.type,
            id: assertionResponse.id,
            rawId: base64UrlEncode(assertionResponse.rawId),
            response: {
              clientDataJSON: assertionResponse.response.clientDataJSON,
              authenticatorData: assertionResponse.response.authenticatorData,
              signature: assertionResponse.response.signature,
              userHandle: assertionResponse.response.userHandle,
            },
          };

          return JSON.stringify(base64Response);
        } else {
          logInfo('Assertion creation failed');
          return JSON.stringify({ error: 'Assertion creation failed' });
        }
      } catch (error) {
        logError('Error creating assertion', error);
        throw error;
      }
    }

    private showPopup(encodedOptions: string, operationType: WebAuthnOperationType, abortSignal: AbortSignal, userName?: string): Promise<string> {
      return new Promise((resolve, reject) => {
        logInfo('Creating and showing popup');
        const options = JSON.parse(atob(encodedOptions));
        const origin = options.origin || window.location.origin;
        const rpId = options.rpId || new URL(origin).hostname;

        const popupOptions: PopupOptions = {
          operationType,
          rpId,
          userName
        };

        const popup = new WebAuthnPopup(popupOptions, {
          onAction: async () => {
            try {
              const result = await (operationType === 'create'
                ? this.handlePasskeySave(encodedOptions)
                : this.handleGetAssertion(encodedOptions));

              popup.setResponse(result);

              const parsedResult = JSON.parse(result);
              if (parsedResult.error) {
                throw new Error(parsedResult.error);
              }

              abortSignal.removeEventListener('abort', abortHandler);
              resolve(result);
            } catch (error: any) {
              if (error.name === 'AbortError') {
                logInfo(`Operation ${operationType} was aborted`);
                abortSignal.removeEventListener('abort', abortHandler);
                reject(error);
              } else {
                logError(`Error during ${operationType} operation`, error);
                reject(error);
              }
            }
          },
          onClose: () => {
            abortSignal.removeEventListener('abort', abortHandler);
            resolve('closed');
          }
        });

        const abortHandler = () => {
          logInfo(`Operation ${operationType} was aborted`);
          popup.hide();
          reject(new DOMException('Operation aborted', 'AbortError'));
        };

        abortSignal.addEventListener('abort', abortHandler);

        popup.show();
      });
    }
  }

  const interceptor = new WebAuthnInterceptor();

  navigator.credentials.create = async function (
    this: CredentialsContainer,
    options?: CredentialCreationOptions
  ): Promise<Credential | null> {
    logInfo('navigator.credentials.create called');
    if (
      await interceptor.shouldIntercept('create') &&
      options &&
      'publicKey' in options &&
      options.publicKey
    ) {
      try {
        const result = await interceptor.interceptCreate(options.publicKey);
        if (result === null) {
          logInfo('Falling back to original create method');
          return await originalCreate.call(this, options);
        }
        return result;
      } catch (error: any) {
        if (error.name === 'AbortError') {
          logInfo('Create operation aborted, falling back to original method');
          return await originalCreate.call(this, options);
        } else {
          logError('Error in intercepted create', error);
          return await originalCreate.call(this, options);
        }
      }
    }
    return originalCreate.call(this, options);
  };

  navigator.credentials.get = async function (
    this: CredentialsContainer,
    options?: CredentialRequestOptions
  ): Promise<Credential | null> {
    logInfo('navigator.credentials.get called');
    if (
      await interceptor.shouldIntercept('get') &&
      options &&
      'publicKey' in options &&
      options.publicKey
    ) {
      try {
        const result = await interceptor.interceptGet(options.publicKey);
        if (result === null) {
          logInfo('Falling back to original get method');
          return await originalGet.call(this, options);
        }
        return result;
      } catch (error: any) {
        if (error.name === 'AbortError') {
          logInfo('Get operation aborted, falling back to original method');
          return await originalGet.call(this, options);
        } else {
          logError('Error in intercepted get', error);
          return await originalGet.call(this, options);
        }
      }
    }
    return originalGet.call(this, options);
  };

  logInfo('WebAuthn interception script fully initialized');
})();
