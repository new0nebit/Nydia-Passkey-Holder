/**
 * Encodes an ArrayBuffer or TypedArray into a base64url string.
 * @param buffer The buffer to encode.
 * @returns The base64url encoded string.
 */
export function base64UrlEncode(buffer: ArrayBuffer | ArrayBufferView): string {
  let bytes: Uint8Array;

  if (buffer instanceof ArrayBuffer) {
    bytes = new Uint8Array(buffer);
  } else if (ArrayBuffer.isView(buffer)) {
    bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } else {
    throw new Error('Input must be an ArrayBuffer or ArrayBufferView');
  }

  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a base64url string into a Uint8Array.
 * @param base64url The base64url string to decode.
 * @returns The decoded Uint8Array.
 */
export function base64UrlDecode(base64url: string): Uint8Array {
  if (typeof base64url !== 'string' || !base64url) {
    console.warn('base64UrlDecode received invalid input');
    return new Uint8Array(0);
  }
  try {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch (error) {
    console.error('Error in base64UrlDecode:', error);
    throw error;
  }
}

/**
 * Converts a base64url string into an ArrayBuffer.
 * @param base64url The base64url string to convert.
 * @returns The decoded ArrayBuffer.
 */
export function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  return base64UrlDecode(base64url).buffer;
}
