// Encodes an ArrayBuffer or Uint8Array into a base64url string.
export function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;

  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  const base64 = btoa(binary);
  
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Decodes a base64url string into a Uint8Array.
export function base64UrlDecode(base64url: string): Uint8Array {
  if (!base64url) return new Uint8Array(0);

  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');
    
  while (base64.length % 4) {
    base64 += '=';
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  
  return bytes;
}
