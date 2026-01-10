import { base64UrlDecode } from '../base64url';

// Create a fresh ArrayBuffer copy; strings are treated as base64url.
export function toArrayBuffer(data: string | ArrayBuffer | ArrayBufferView): ArrayBuffer {
  if (typeof data === 'string') {
    return base64UrlDecode(data).slice().buffer;
  }

  if (data instanceof ArrayBuffer) {
    return data.slice(0);
  }

  const view = data as ArrayBufferView;
  const copy = new Uint8Array(view.byteLength);
  copy.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
  return copy.buffer;
}
