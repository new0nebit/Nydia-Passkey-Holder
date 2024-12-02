export type WebAuthnOperationType = 'create' | 'get';

export interface StoredCredential {
  uniqueId: string;
  credentialId: string;
  rpId: string;
  userIdHash: string;
  privateKey: string;
  userHandle: string;
  publicKey: string;
  publicKeyAlgorithm: number;
  counter: number;
  userName?: string;
  isSynced?: boolean;
}

export interface Account {
  username: string;
  userHandle: string;
  credentialId: string;
  uniqueId: string;
}

export interface RenterdSettings {
  password: string;
  serverAddress: string;
  serverPort: number;
  bucketName: string;
}