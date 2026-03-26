(() => {
  // Abort early if the Credential Management API is unavailable
  if (!('credentials' in navigator)) return;

  console.info('[Injector] WebAuthn injector initialized');

  // Convert base64url-encoded string to ArrayBuffer
  const toArrayBuffer = (base64url: string): ArrayBuffer => {
    const binaryString = atob(base64url.replace(/-/g, '+').replace(/_/g, '/'));
    const bufferLength = binaryString.length;
    const bytes = new Uint8Array(bufferLength);
    for (let i = 0; i < bufferLength; ++i) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };

  // Convert any BufferSource to base64url-encoded string
  const toBase64url = (bufferSource: BufferSource): string => {
    const bytes = toUint8Array(bufferSource);

    let binaryString = '';
    for (let i = 0; i < bytes.length; ++i) {
      binaryString += String.fromCharCode(bytes[i]);
    }
    return btoa(binaryString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  // Remove AbortSignal to avoid DataClone errors
  const stripSignal = <T extends { signal?: unknown }>(options: T): Omit<T, 'signal'> => {
    const { signal, ...rest } = options as { signal?: unknown } & Record<string, unknown>;
    void signal; // Explicitly mark as unused
    return rest as Omit<T, 'signal'>;
  };

  // Normalize any BufferSource to Uint8Array
  const toUint8Array = (source: BufferSource): Uint8Array => {
    if (source instanceof ArrayBuffer) {
      return new Uint8Array(source);
    }
    // ArrayBufferView: TypedArray or DataView
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  };

  type PublicKeyOptions = {
    publicKey?: {
      challenge?: BufferSource | string;
      user?: { id?: BufferSource | string; [key: string]: unknown };
      allowCredentials?: Array<{ id: BufferSource | string; [key: string]: unknown }>;
      excludeCredentials?: Array<{ id: BufferSource | string; [key: string]: unknown }>;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };

  // Check if value is BufferSource (ArrayBuffer or ArrayBufferView)
  const isBufferSource = (value: unknown): value is BufferSource =>
    value instanceof ArrayBuffer || ArrayBuffer.isView(value);

  // Serialize BufferSource values inside publicKey options into base64url strings
  const serializeOptions = (options: PublicKeyOptions): PublicKeyOptions => {
    const serializedOptions: PublicKeyOptions = { ...options };
    if (!serializedOptions.publicKey) return serializedOptions;

    const pkOptions = (serializedOptions.publicKey = { ...serializedOptions.publicKey });

    if (isBufferSource(pkOptions.challenge)) pkOptions.challenge = toBase64url(pkOptions.challenge);

    if (pkOptions.user?.id && isBufferSource(pkOptions.user.id)) {
      pkOptions.user = { ...pkOptions.user, id: toBase64url(pkOptions.user.id) };
    }

    // Handle arrays of credentials that need id conversion
    const serializeCredentialDescriptors = (
      descriptors?: Array<{ id: BufferSource | string; [key: string]: unknown }>,
    ): Array<{ id: string; [key: string]: unknown }> | undefined =>
      descriptors?.map((descriptor) => ({
        ...descriptor,
        id: typeof descriptor.id === 'string' ? descriptor.id : toBase64url(descriptor.id),
      }));

    pkOptions.allowCredentials = serializeCredentialDescriptors(pkOptions.allowCredentials);
    pkOptions.excludeCredentials = serializeCredentialDescriptors(pkOptions.excludeCredentials);

    return serializedOptions;
  };

  // Convert raw response data to native-like WebAuthn response objects
  const asAuthenticatorResponse = (
    rawResponse: Record<string, unknown>,
  ): AuthenticatorAttestationResponse | AuthenticatorAssertionResponse => {
    if ('attestationObject' in rawResponse) {
      // Registration flow: Attestation response (for credential creation)
      const attestationResponse: Record<string, unknown> = {
        clientDataJSON: toArrayBuffer(rawResponse.clientDataJSON as string),
        attestationObject: toArrayBuffer(rawResponse.attestationObject as string),
        getTransports: () => ['internal', 'hybrid'],
      };

      // Optional get methods
      if (rawResponse.publicKeyDER)
        attestationResponse.getPublicKey = () => toArrayBuffer(rawResponse.publicKeyDER as string);
      if (rawResponse.authenticatorData) {
        attestationResponse.getAuthenticatorData = () =>
          toArrayBuffer(rawResponse.authenticatorData as string);
      }
      if (rawResponse.publicKeyAlgorithm !== undefined) {
        attestationResponse.getPublicKeyAlgorithm = () => rawResponse.publicKeyAlgorithm;
      }

      // Set the prototype to match native browser implementations
      Object.setPrototypeOf(attestationResponse, AuthenticatorAttestationResponse.prototype);
      return attestationResponse as unknown as AuthenticatorAttestationResponse;
    }

    // Assertion response
    const assertionResponse: Record<string, unknown> = {
      clientDataJSON: toArrayBuffer(rawResponse.clientDataJSON as string),
      authenticatorData: toArrayBuffer(rawResponse.authenticatorData as string),
      signature: toArrayBuffer(rawResponse.signature as string),
      userHandle: rawResponse.userHandle ? toArrayBuffer(rawResponse.userHandle as string) : null,
    };
    Object.setPrototypeOf(assertionResponse, AuthenticatorAssertionResponse.prototype);
    return assertionResponse as unknown as AuthenticatorAssertionResponse;
  };

  // Create a PublicKeyCredential object with correct prototype chain
  const asPublicKeyCredential = (rawCredential: Record<string, unknown>): PublicKeyCredential => {
    const credential: Record<string, unknown> = {
      id: rawCredential.id,
      rawId: toArrayBuffer(rawCredential.rawId as string),
      response: asAuthenticatorResponse(rawCredential.response as Record<string, unknown>),
      type: rawCredential.type ?? 'public-key',
      authenticatorAttachment: 'platform',
      // Return resident key capability
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
    Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
    return credential as unknown as PublicKeyCredential;
  };

  type Operation = 'create' | 'get';
  type CredentialOptions = CredentialCreationOptions | CredentialRequestOptions;
  type CredentialMethod<T extends CredentialOptions> =
    (options?: T) => Promise<Credential | null>;

  // Returns a wrapper that intercepts create/get calls
  const wrap =
    <T extends CredentialOptions>(
      operation: Operation,
      original: CredentialMethod<T>,
    ): CredentialMethod<T> =>
    (options?: T) => {
      // Bypass for non-WebAuthn calls
      if (!options || !('publicKey' in options)) {
        return original(options);
      }

      // Set up message types for communication with the dispatcher
      const messageTypePrefix = `webauthn-${operation}`;
      const RESPONSE = `${messageTypePrefix}-response`;
      const ERROR = `${messageTypePrefix}-error`;
      const FALLBACK = `${messageTypePrefix}-fallback`;

      return new Promise((resolve, reject) => {
        // Set up one-time message listener for WebAuthn response
        const handleWindowMessage = (event: MessageEvent) => {
          if (event.source !== window) return;
          const { type, response, error } = (event.data as {
            type?: string;
            response?: unknown;
            error?: string;
          }) || {};

          switch (type) {
            case RESPONSE:
              window.removeEventListener('message', handleWindowMessage);
              try {
                // Transform raw response into a proper credential object
                resolve(asPublicKeyCredential(response as Record<string, unknown>));
              } catch (err: unknown) {
                reject(
                  new DOMException(
                    `Error transforming credential: ${
                      err instanceof Error ? err.message : String(err)
                    }`,
                    'NotAllowedError',
                  ),
                );
              }
              break;

            case ERROR:
              window.removeEventListener('message', handleWindowMessage);
              reject(new DOMException(error, 'NotAllowedError'));
              break;

            case FALLBACK:
              // Fallback to native WebAuthn flow
              window.removeEventListener('message', handleWindowMessage);
              original(options).then(resolve).catch(reject);
              break;

            case undefined:
              break;
          }
        };

        window.addEventListener('message', handleWindowMessage);
        // Send the WebAuthn request to the dispatcher after preparing options
        const payload = serializeOptions(stripSignal(options) as PublicKeyOptions);
        window.postMessage({ type: messageTypePrefix, options: payload }, '*');
      });
    };

  type CredentialsLike = typeof navigator.credentials & {
    store?: typeof navigator.credentials.store;
    preventSilentAccess?: typeof navigator.credentials.preventSilentAccess;
  };

  // Build a custom navigator.credentials wrapper that intercepts create/get calls
  const nativeCredentials = navigator.credentials;
  const nydiaCredentials: CredentialsLike = {
    create: wrap('create', nativeCredentials.create.bind(nativeCredentials)),
    get: wrap('get', nativeCredentials.get.bind(nativeCredentials)),
    store: nativeCredentials.store?.bind(nativeCredentials),
    preventSilentAccess: nativeCredentials.preventSilentAccess?.bind(nativeCredentials),
  };

  // Replace the entire credentials object with custom implementation
  Object.defineProperty(navigator, 'credentials', {
    value: nydiaCredentials,
    writable: true,
    configurable: true,
  });

  // Emulate platform authenticator presence
  if ('PublicKeyCredential' in window) {
    const publicKeyCredentialStatics =
      window.PublicKeyCredential as unknown as Record<string, unknown>;
    publicKeyCredentialStatics.isUserVerifyingPlatformAuthenticatorAvailable = () =>
      Promise.resolve(true);
    publicKeyCredentialStatics.isConditionalMediationAvailable = () => Promise.resolve(true);
  }
})();
