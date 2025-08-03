(() => {
  // Abort early if the Credential Management API is unavailable
  if (!('credentials' in navigator)) return;

  console.log('[Injector] WebAuthn injector initialized');

  // Convert base64url-encoded string to ArrayBuffer
  const toArrayBuffer = (b64: string): ArrayBuffer => {
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const len = bin.length;
    const view = new Uint8Array(len);
    for (let i = 0; i < len; ++i) view[i] = bin.charCodeAt(i);
    return view.buffer;
  };

  // Convert ArrayBuffer to base64url-encoded string
  const toBase64url = (buf: ArrayBuffer): string => {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; ++i) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  // Remove AbortSignal to avoid DataClone errors
  const stripSignal = <T extends { signal?: unknown }>(obj: T): Omit<T, 'signal'> => {
    const { signal, ...rest } = obj as any;
    return rest;
  };

  // Serialize ArrayBuffer values inside publicKey options into base64url strings
  const serializeOptions = (opts: any): any => {
    const out = { ...opts, origin: location.origin };
    if (!out.publicKey) return out;

    const pk = (out.publicKey = { ...out.publicKey });

    if (pk.challenge instanceof ArrayBuffer) pk.challenge = toBase64url(pk.challenge);

    if (pk.user?.id instanceof ArrayBuffer) {
      pk.user = { ...pk.user, id: toBase64url(pk.user.id) };
    }

    // Handle arrays of credentials that need id conversion
    const rewrite = (arr?: any[]) => arr?.map((d) => ({ ...d, id: toBase64url(d.id) }));

    pk.allowCredentials = rewrite(pk.allowCredentials);
    pk.excludeCredentials = rewrite(pk.excludeCredentials);

    return out;
  };

  // Convert raw response data to native-like WebAuthn response objects
  const asAuthenticatorResponse = (
    src: any,
  ): AuthenticatorAttestationResponse | AuthenticatorAssertionResponse => {
    if ('attestationObject' in src) {
      // Registration flow: Attestation response (for credential creation)
      const att: any = {
        clientDataJSON: toArrayBuffer(src.clientDataJSON),
        attestationObject: toArrayBuffer(src.attestationObject),
        getTransports: () => ['internal', 'hybrid'],
      };

      // Optional get methods
      if (src.publicKeyDER) att.getPublicKey = () => toArrayBuffer(src.publicKeyDER);
      if (src.authenticatorData) att.getAuthenticatorData = () => toArrayBuffer(src.authenticatorData);
      if (src.publicKeyAlgorithm !== undefined) att.getPublicKeyAlgorithm = () => src.publicKeyAlgorithm;

      // Set the prototype to match native browser implementations
      Object.setPrototypeOf(att, AuthenticatorAttestationResponse.prototype);
      return att;
    }

    // Assertion response
    const asr: any = {
      clientDataJSON: toArrayBuffer(src.clientDataJSON),
      authenticatorData: toArrayBuffer(src.authenticatorData),
      signature: toArrayBuffer(src.signature),
      userHandle: src.userHandle ? toArrayBuffer(src.userHandle) : null,
    };
    Object.setPrototypeOf(asr, AuthenticatorAssertionResponse.prototype);
    return asr;
  };

  // Create a PublicKeyCredential object with correct prototype chain
  const asPublicKeyCredential = (raw: any): PublicKeyCredential => {
    const cred: any = {
      id: raw.id,
      rawId: toArrayBuffer(raw.rawId),
      response: asAuthenticatorResponse(raw.response),
      type: raw.type ?? 'public-key',
      authenticatorAttachment: 'platform',
      // Return resident key capability
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred;
  };

  type Op = 'create' | 'get';

  // Returns a wrapper that intercepts create/get calls
  const wrap =
    (op: Op, original: (o?: any) => Promise<any>) =>
    (options?: any): Promise<any> => {
      // Bypass for non‑WebAuthn calls
      if (!options || !('publicKey' in options))
        return original.call(navigator.credentials, options);

      // Set up message types for communication with the WebAuthn handler
      const base = `webauthn-${op}`;
      const RESPONSE = `${base}-response`;
      const ERROR = `${base}-error`;
      const FALLBACK = `${base}-fallback`;

      return new Promise((resolve, reject) => {
        // Set up one-time message listener for WebAuthn response
        const handler = (e: MessageEvent) => {
          if (e.source !== window) return;
          const { type, response, error } = e.data || {};
          switch (type) {
            case RESPONSE:
              window.removeEventListener('message', handler);
              try {
                // Transform raw response into a proper credential object
                resolve(asPublicKeyCredential(response));
              } catch (err: any) {
                reject(
                  new DOMException(
                    `Error transforming credential: ${err.message}`,
                    'NotAllowedError',
                  ),
                );
              }
              break;

            case ERROR:
              window.removeEventListener('message', handler);
              reject(new DOMException(error, 'NotAllowedError'));
              break;

            case FALLBACK:
              // Fallback to native WebAuthn flow
              window.removeEventListener('message', handler);
              original.call(navigator.credentials, options).then(resolve).catch(reject);
              break;
          }
        };

        window.addEventListener('message', handler);
        // Send the WebAuthn request to handler after preparing options
        const payload = serializeOptions(stripSignal(options));
        window.postMessage({ type: base, options: payload }, '*');
      });
    };

  type CredsLike = typeof navigator.credentials & {
    store?: typeof navigator.credentials.store;
    preventSilentAccess?: typeof navigator.credentials.preventSilentAccess;
  };

  // Build a custom navigator.credentials wrapper that intercepts create/get calls
  const orig = navigator.credentials;
  const nydiaCredentials: CredsLike = {
    create: wrap('create', orig.create.bind(orig)),
    get: wrap('get', orig.get.bind(orig)),
    store: orig.store?.bind(orig),
    preventSilentAccess: orig.preventSilentAccess?.bind(orig),
  };

  // Replace the entire credentials object with custom implementation
  Object.defineProperty(navigator, 'credentials', {
    value: nydiaCredentials,
    writable: true,
    configurable: true,
  });

  // Emulate platform authenticator presence
  if ('PublicKeyCredential' in window) {
    const pkc: any = window.PublicKeyCredential;
    pkc.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    pkc.isConditionalMediationAvailable = async () => true;
  }
})();
