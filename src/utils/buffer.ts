import { base64UrlDecode } from './base64url';

// Create a fresh ArrayBuffer copy; strings are treated as base64url.
export function toArrayBuffer(data: string | ArrayBuffer | Uint8Array): ArrayBuffer {
  if (typeof data === 'string') {
    return base64UrlDecode(data).slice().buffer;
  }

  if (data instanceof ArrayBuffer) {
    return data.slice(0);
  }

  return data.slice().buffer;
}
