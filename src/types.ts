export type WebAuthnOperationType = 'create' | 'get';

export type BinaryLike = ArrayBuffer | Uint8Array;
export type BinaryOrBase64 = BinaryLike | string;

export type PublicKeyCredentialCreationOptions =
  globalThis.PublicKeyCredentialCreationOptions;
export type PublicKeyCredentialRequestOptions =
  globalThis.PublicKeyCredentialRequestOptions;

export interface SerializedCredentialDescriptor {
  id: string | BinaryLike;
  type?: string;
  transports?: string[];
}

export interface SerializedCreationOptions {
  publicKey: {
    rp: { id?: string; name?: string };
    user: {
      id: string | BinaryLike;
      name: string;
      displayName?: string;
    };
    challenge: string | BinaryLike;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    excludeCredentials?: SerializedCredentialDescriptor[];
  };
  origin?: string;
}

export interface SerializedRequestOptions {
  publicKey: {
    challenge: string | BinaryLike;
    rpId?: string;
    allowCredentials?: SerializedCredentialDescriptor[];
  };
  origin?: string;
}

export type SerializedPublicKeyOptions =
  | SerializedCreationOptions
  | SerializedRequestOptions;

export interface CredentialCreationOptions {
  publicKey: Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user'> & {
    challenge: BinaryLike;
    user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: BinaryOrBase64 };
    rpId?: string;
  };
  origin: string;
}

export interface GetAssertionOptions {
  publicKey: Omit<PublicKeyCredentialRequestOptions, 'challenge'> & {
    challenge: BinaryOrBase64;
  };
  origin: string;
}

export interface StoredCredential {
  uniqueId: string;
  credentialId: string;
  rpId: string;
  privateKey: string;
  iv: string;
  userHandle: string;
  publicKeyAlgorithm: number;
  counter: number;
  userName?: string;
  creationTime: number;
  isSynced: boolean;
}

export interface Account {
  username: string;
  userHandle: string;
  credentialId: string;
  uniqueId: string;
  creationTime?: number;
}

export interface RenterdSettings {
  password: string;
  serverAddress: string;
  serverPort: number;
  bucketName: string;
  serverProtocol?: 'http' | 'https';
}

export interface EncryptedRecord {
  uniqueId: string;
  iv: string;
  data: string;
  isSynced: boolean;
}

export interface BackgroundMessage {
  type: string;
  options?: SerializedPublicKeyOptions | GetAssertionOptions | CredentialCreationOptions;
  rpId?: string;
  selectedCredentialId?: string;
  uniqueId?: string;
  uniqueIds?: string[];
  wrappedKey?: number[];
  [key: string]: unknown;
}

export interface AttestationResponse {
  type: 'public-key';
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    authenticatorData: string;
    publicKeyAlgorithm: number;
    publicKeyDER: string;
  };
}

export interface AssertionResponse {
  type: 'public-key';
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
}
