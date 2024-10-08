(() => {
    console.log('Launching WebAuthn interception script');

    const originalCreate = navigator.credentials.create.bind(navigator.credentials);
    const originalGet = navigator.credentials.get.bind(navigator.credentials);

    type WebAuthnOperationType = 'create' | 'get';

    class WebAuthnInterceptor {
        private interceptEnabled: boolean;
        private currentOperation: Promise<PublicKeyCredential | null> | null;

        constructor() {
            console.log('WebAuthnInterceptor has been created');
            this.interceptEnabled = true;
            this.currentOperation = null;
        }

        async shouldIntercept(): Promise<boolean> {
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
            console.log(`Intercepting WebAuthn ${type} operation`);

            if (!options || typeof options !== 'object') {
                console.error(`Error: Invalid options provided for ${type}`);
                throw new DOMException("Invalid options", "NotAllowedError");
            }

            if (this.currentOperation) {
                await this.currentOperation;
            }

            this.currentOperation = new Promise<PublicKeyCredential | null>(async (resolve, reject) => {
                try {
                    const cleanedOptions = this.cleanOptions(options, window.location.origin);
                    const encodedOptions = btoa(JSON.stringify(cleanedOptions));
                    console.log(`Encoded PublicKeyCredential${type === 'create' ? 'Creation' : 'Request'}Options:`, encodedOptions);

                    const result = await this.showPopup(encodedOptions, type);

                    if (result === 'closed') {
                        console.log(`Popup closed, falling back to native WebAuthn ${type} flow`);
                        resolve(null);
                    } else {
                        const parsedResult = JSON.parse(result);
                        const credential = WebAuthnInterceptor.processAuthenticatorResponse(parsedResult, type);
                        resolve(credential);
                    }
                } catch (error) {
                    console.error("Error in WebAuthn operation", error);
                    reject(error);
                } finally {
                    this.currentOperation = null;
                }
            });

            return this.currentOperation;
        }

        private cleanOptions(
            options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
            origin: string
        ): any {
            const cleanedOptions: any = {
                publicKey: {},
                origin,
                rpId: ('rp' in options && options.rp && 'id' in options.rp) ? options.rp.id : new URL(origin).hostname
            };

            if ('rp' in options) cleanedOptions.publicKey.rp = options.rp;

            if ('user' in options && options.user) {
                cleanedOptions.publicKey.user = {
                    ...options.user,
                    id: this.bufferSourceToBase64(options.user.id)
                };
            }

            if ('challenge' in options) {
                cleanedOptions.publicKey.challenge = this.bufferSourceToBase64(options.challenge);
            }

            if ('pubKeyCredParams' in options) cleanedOptions.publicKey.pubKeyCredParams = options.pubKeyCredParams;

            if ('timeout' in options) cleanedOptions.publicKey.timeout = options.timeout;

            if ('excludeCredentials' in options) {
                cleanedOptions.publicKey.excludeCredentials = options.excludeCredentials && options.excludeCredentials.length > 0
                    ? options.excludeCredentials.map(cred => ({
                        ...cred,
                        id: this.bufferSourceToBase64(cred.id)
                    }))
                    : [];
            }

            if ('authenticatorSelection' in options) cleanedOptions.publicKey.authenticatorSelection = options.authenticatorSelection;

            if ('attestation' in options) cleanedOptions.publicKey.attestation = options.attestation;

            if ('extensions' in options) cleanedOptions.publicKey.extensions = options.extensions;

            if ('allowCredentials' in options) {
                cleanedOptions.publicKey.allowCredentials = options.allowCredentials?.map(cred => ({
                    ...cred,
                    id: this.bufferSourceToBase64(cred.id)
                }));
            }

            return cleanedOptions;
        }

        private bufferSourceToBase64(buffer: BufferSource): string {
            let arrayBuffer: ArrayBuffer;
            if (buffer instanceof ArrayBuffer) {
                arrayBuffer = buffer;
            } else if (ArrayBuffer.isView(buffer)) {
                arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
            } else {
                throw new Error('Unsupported BufferSource type');
            }
            return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
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
                getClientExtensionResults: () => ({ credProps: { rk: true } }),
                authenticatorAttachment: 'platform'
            };

            return credential;
        }

        private static base64ToArrayBuffer(input: string): ArrayBuffer {
            const binary = atob(input.replace(/-/g, '+').replace(/_/g, '/'));
            const len = binary.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        private showPopup(encodedOptions: string, operationType: WebAuthnOperationType): Promise<string> {
            return new Promise((resolve) => {
                console.log("Creating and showing popup");
                const popup = document.createElement('div');
                popup.id = 'webauthn-popup';
                popup.style.position = 'fixed';
                popup.style.top = '30%';
                popup.style.left = '50%';
                popup.style.transform = 'translate(-50%, -50%)';
                popup.style.backgroundColor = '#fff';
                popup.style.padding = '20px';
                popup.style.boxShadow = '0 0 10px rgba(0,0,0,0.5)';
                popup.style.zIndex = '1000';

                const title = document.createElement('h3');
                title.textContent = `Encoded Options (${operationType})`;
                popup.appendChild(title);

                const content = document.createElement('textarea');
                content.value = encodedOptions;
                content.readOnly = true;
                content.rows = 5;
                content.cols = 60;
                popup.appendChild(content);

                const responseInput = document.createElement('textarea');
                responseInput.placeholder = `Authenticator${operationType === 'create' ? 'Attestation' : 'Assertion'}Response`;
                responseInput.rows = 10;
                responseInput.cols = 60;
                popup.appendChild(responseInput);

                const buttonContainer = document.createElement('div');
                buttonContainer.className = 'button-container';
                buttonContainer.style.marginTop = '10px';
                buttonContainer.style.display = 'flex';
                buttonContainer.style.justifyContent = 'center';

                const createButton = (text: string, onClick: () => void) => {
                    const button = document.createElement('button');
                    button.textContent = text;
                    button.onclick = onClick;
                    button.style.marginRight = '1px';
                    return button;
                };

                const copyButton = createButton('Copy', () => {
                    content.select();
                    document.execCommand('copy');
                });
                buttonContainer.appendChild(copyButton);

                const getPublicKeyButton = createButton('getPublicKey()', () => {
                    try {
                        const response = JSON.parse(responseInput.value);
                        if (response && response.response && response.response.publicKey) {
                            const publicKeyArray = response.response.publicKey.split(', ').map(Number);
                            const publicKeyArrayBuffer = new Uint8Array(publicKeyArray).buffer;
                            const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyArrayBuffer)));
                            console.log("Public Key (Base64):", publicKeyBase64);
                        } else {
                            console.error("Public key not found in the response");
                        }
                    } catch (error) {
                        console.error("Error extracting Public Key:", error);
                    }
                });
                buttonContainer.appendChild(getPublicKeyButton);

                const sendButton = createButton('SEND', () => {
                    try {
                        const response = responseInput.value;
                        const parsedResponse = JSON.parse(response);

                        if (!parsedResponse.type || !parsedResponse.id || !parsedResponse.response) {
                            throw new Error('Invalid response format');
                        }

                        const getField = (obj: any, fieldName: string) => {
                            const variants = [
                                fieldName,
                                fieldName.toLowerCase(),
                                fieldName.replace(/([A-Z])/g, '_$1').toLowerCase(),
                                fieldName.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
                            ];
                            for (const variant of variants) {
                                if (obj.hasOwnProperty(variant)) {
                                    return obj[variant];
                                }
                            }
                            return undefined;
                        };

                        const requiredFields = operationType === 'create' 
                            ? ['clientDataJSON', 'attestationObject']
                            : ['clientDataJSON', 'authenticatorData', 'signature'];

                        for (const field of requiredFields) {
                            if (getField(parsedResponse.response, field) === undefined) {
                                throw new Error(`Missing required field: ${field}`);
                            }
                        }

                        const finalResponse = {
                            type: parsedResponse.type,
                            id: parsedResponse.id,
                            rawId: parsedResponse.rawId || parsedResponse.raw_id || parsedResponse.id,
                            response: {
                                clientDataJSON: getField(parsedResponse.response, 'clientDataJSON'),
                                ...(operationType === 'create' 
                                    ? { 
                                        attestationObject: getField(parsedResponse.response, 'attestationObject'),
                                        publicKey: parsedResponse.response.publicKey,
                                        publicKeyAlgorithm: parsedResponse.response.publicKeyAlgorithm
                                      }
                                    : {
                                        authenticatorData: getField(parsedResponse.response, 'authenticatorData'),
                                        signature: getField(parsedResponse.response, 'signature'),
                                        userHandle: getField(parsedResponse.response, 'userHandle')
                                      }
                                )
                            }
                        };

                        document.body.removeChild(popup);
                        resolve(JSON.stringify(finalResponse));
                    } catch (error) {
                        console.error("Error: Invalid input", error);
                        if (error instanceof Error) {
                            alert('Invalid input. Please check your JSON format and ensure all required fields are present and properly encoded. Error: ' + error.message);
                        } else {
                            alert('An unknown error occurred');
                        }
                    }
                });
                buttonContainer.appendChild(sendButton);

                const closeButton = createButton('Close', () => {
                    document.body.removeChild(popup);
                    resolve('closed');
                });
                closeButton.style.marginRight = '0';
                buttonContainer.appendChild(closeButton);

                popup.appendChild(buttonContainer);
                document.body.appendChild(popup);
            });
        }
    }

    const interceptor = new WebAuthnInterceptor();

    navigator.credentials.create = async function(this: CredentialsContainer, options?: CredentialCreationOptions): Promise<Credential | null> {
        console.log('navigator.credentials.create called');
        if (await interceptor.shouldIntercept() && options && 'publicKey' in options && options.publicKey) {
            try {
                const result = await interceptor.interceptCreate(options.publicKey);
                if (result === null) {
                    return await originalCreate.call(this, options);
                }
                return result;
            } catch (error) {
                console.error('Error in intercepted create:', error);
                throw error;
            }
        }
        return originalCreate.call(this, options);
    };

    navigator.credentials.get = async function(this: CredentialsContainer, options?: CredentialRequestOptions): Promise<Credential | null> {
        console.log('navigator.credentials.get called');
        if (await interceptor.shouldIntercept() && options && 'publicKey' in options && options.publicKey) {
            try {
                const result = await interceptor.interceptGet(options.publicKey);
                if (result === null) {
                    return originalGet.call(this, options);
                }
                return result;
            } catch (error) {
                console.error('Error in intercepted get:', error);
                return originalGet.call(this, options);
            }
        }
        return originalGet.call(this, options);
    };

    console.log('WebAuthn interception script setup completed');
})();
