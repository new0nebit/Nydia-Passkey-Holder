export type WebAuthnOperationType = 'create' | 'get';

export interface StoredCredential {
  uniqueId: string;
  credentialId: string;
  rpId: string;
  userIdHash: string;
  privateKey: string;
  iv: string;
  userHandle: string;
  publicKey: string;
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
}

export interface EncryptedRecord {
  uniqueId: string;
  iv: string;
  data: string;
  isSynced: boolean;
}