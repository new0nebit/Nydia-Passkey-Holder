// Check if Credential Management API is available
(function () {
  if (!('credentials' in navigator)) {
    return;
  }

  // Preserve original methods.
  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  // Override credentials.create to intercept WebAuthn credential creation.
  navigator.credentials.create = async function (options) {
    if (!options || !('publicKey' in options)) {
      // If not a WebAuthn operation, use the original method
      return originalCreate.call(this, options);
    }

    return new Promise((resolve, reject) => {
      const messageHandler = (event) => {
        if (event.source !== window) return;
        const message = event.data;

        if (message.type === 'webauthn-create-response') {
          window.removeEventListener('message', messageHandler);
          resolve(transformCredential(message.response));
        } else if (message.type === 'webauthn-create-error') {
          window.removeEventListener('message', messageHandler);
          reject(new DOMException(message.error, 'NotAllowedError'));
        } else if (message.type === 'webauthn-create-fallback') {
          window.removeEventListener('message', messageHandler);
          // Fallback to the original method
          originalCreate.call(navigator.credentials, options).then(resolve).catch(reject);
        }
      };

      window.addEventListener('message', messageHandler);

      // Remove the signal property if it exists, as we handle cancellation through our own abort mechanism.
      const optionsWithoutSignal = { ...options };
      delete optionsWithoutSignal.signal;

      const serializedOptions = serializePublicKeyCredentialOptions(optionsWithoutSignal);

      // Send a message to the content script
      window.postMessage({ type: 'webauthn-create', options: serializedOptions }, '*');
    });
  };

  // Overrides navigator.credentials.get to intercept WebAuthn credential retrieval.
  navigator.credentials.get = async function (options) {
    if (!options || !('publicKey' in options)) {
      // If not a WebAuthn operation, use the original method
      return originalGet.call(this, options);
    }

    return new Promise((resolve, reject) => {
      const messageHandler = (event) => {
        if (event.source !== window) return;
        const message = event.data;

        if (message.type === 'webauthn-get-response') {
          window.removeEventListener('message', messageHandler);
          resolve(transformCredential(message.response));
        } else if (message.type === 'webauthn-get-error') {
          window.removeEventListener('message', messageHandler);
          reject(new DOMException(message.error, 'NotAllowedError'));
        } else if (message.type === 'webauthn-get-fallback') {
          window.removeEventListener('message', messageHandler);
          // Fallback to the original method
          originalGet.call(navigator.credentials, options).then(resolve).catch(reject);
        }
      };

      window.addEventListener('message', messageHandler);

      // Remove the signal property if it exists, as we do not use it.
      const optionsWithoutSignal = { ...options };
      delete optionsWithoutSignal.signal;

      const serializedOptions = serializePublicKeyCredentialOptions(optionsWithoutSignal);

      // Send a message to the content script.
      window.postMessage({ type: 'webauthn-get', options: serializedOptions }, '*');
    });
  };

  /* ================================================
     Helper Functions
  =============================================== */

  // Transform credential data from content script into a Credential object.
  function transformCredential(data) {
    console.log('[Injector] Transforming credential:', data);

    const credential = {
      type: data.type,
      id: data.id,
      rawId: base64ToArrayBuffer(data.rawId),
      response: transformAuthenticatorResponse(data.response),
      getClientExtensionResults: () => ({}),
      authenticatorAttachment: data.authenticatorAttachment || null,
    };

    console.log('[Injector] Transformed credential:', credential);
    return credential;
  }

  // Transform authenticator response data into proper response object.
  function transformAuthenticatorResponse(response) {
    console.log('[Injector] Transforming authenticator response:', response);

    if ('attestationObject' in response) {
      // Handle AuthenticatorAttestationResponse
      const attestationResponse = {
        clientDataJSON: base64ToArrayBuffer(response.clientDataJSON),
        attestationObject: base64ToArrayBuffer(response.attestationObject),
      };

      // Add optional methods if data is available
      if (response.publicKeyDER) {
        const publicKeyDERArrayBuffer = base64ToArrayBuffer(response.publicKeyDER);
        attestationResponse.getPublicKey = function () {
          return publicKeyDERArrayBuffer;
        };
        console.log('[Injector] Added getPublicKey method to attestationResponse');
      }

      if (response.authenticatorData) {
        const authenticatorDataArrayBuffer = base64ToArrayBuffer(response.authenticatorData);
        attestationResponse.getAuthenticatorData = function () {
          return authenticatorDataArrayBuffer;
        };
        console.log('[Injector] Added getAuthenticatorData method to attestationResponse');
      }

      if (response.publicKeyAlgorithm !== undefined) {
        const publicKeyAlgorithm = response.publicKeyAlgorithm;
        attestationResponse.getPublicKeyAlgorithm = function () {
          return publicKeyAlgorithm;
        };
        console.log(
          '[Injector] Added getPublicKeyAlgorithm method to attestationResponse:',
          publicKeyAlgorithm,
        );
      }

      // Add getTransports() method
      attestationResponse.getTransports = function () {
        return ['internal', 'hybrid'];
      };
      console.log('[Injector] Added getTransports method to attestationResponse');

      console.log('[Injector] Transformed attestationResponse:', attestationResponse);
      return attestationResponse;
    } else {
      // Handle AuthenticatorAssertionResponse
      return {
        clientDataJSON: base64ToArrayBuffer(response.clientDataJSON),
        authenticatorData: base64ToArrayBuffer(response.authenticatorData),
        signature: base64ToArrayBuffer(response.signature),
        userHandle: response.userHandle ? base64ToArrayBuffer(response.userHandle) : null,
      };
    }
  }

  // Converts a base64url-encoded string to an ArrayBuffer.
  function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Converts an ArrayBuffer to a base64url-encoded string.
  function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  // Serializes PublicKeyCredential options by converting ArrayBuffers to base64url strings.
  function serializePublicKeyCredentialOptions(options) {
    const serializedOptions = { ...options };

    if (options.publicKey) {
      serializedOptions.publicKey = { ...options.publicKey };

      if (options.publicKey.challenge && options.publicKey.challenge instanceof ArrayBuffer) {
        serializedOptions.publicKey.challenge = arrayBufferToBase64Url(options.publicKey.challenge);
      }

      if (
        options.publicKey.user &&
        options.publicKey.user.id &&
        options.publicKey.user.id instanceof ArrayBuffer
      ) {
        serializedOptions.publicKey.user = { ...options.publicKey.user };
        serializedOptions.publicKey.user.id = arrayBufferToBase64Url(options.publicKey.user.id);
      }

      if (options.publicKey.excludeCredentials) {
        serializedOptions.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(
          (cred) => ({
            ...cred,
            id: arrayBufferToBase64Url(cred.id),
          }),
        );
      }

      if (options.publicKey.allowCredentials) {
        serializedOptions.publicKey.allowCredentials = options.publicKey.allowCredentials.map(
          (cred) => ({
            ...cred,
            id: arrayBufferToBase64Url(cred.id),
          }),
        );
      }
    }

    return serializedOptions;
  }
})();
