const MAX_ICON_BYTES = 64 * 1024;

// Raster format signatures
const SIGNATURES = ['\x89PNG\r\n\x1a\n', '\xff\xd8\xff', 'GIF8', '\x00\x00\x01\x00', '\x00\x00\x02\x00', 'BM'];

function isImageData(subtype: string, bytes: string): boolean {
  // SVG only as image/svg+xml
  if (subtype.toLowerCase() === 'svg+xml') return /^(\xef\xbb\xbf)?\s*</.test(bytes) && /<svg[\s>]/i.test(bytes);
  if (bytes.startsWith('RIFF') && bytes.slice(8, 12) === 'WEBP') return true;
  if (['ftypavif', 'ftypavis'].includes(bytes.slice(4, 12))) return true;
  return SIGNATURES.some((signature) => bytes.startsWith(signature));
}

export function isSiteIcon(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_ICON_BYTES / 3) * 4 + 128) {
    return false;
  }
  const match = /^data:image\/([a-z0-9.+-]+)(?:;charset=[a-z0-9-]+)?;base64,([a-z0-9+/]+={0,2})$/i.exec(value);
  if (!match) return false;
  try {
    const bytes = atob(match[2]);
    return bytes.length > 0 && bytes.length <= MAX_ICON_BYTES && isImageData(match[1], bytes);
  } catch {
    return false;
  }
}

// Stops at the size limit
async function readLimited(response: Response): Promise<Uint8Array | null> {
  if (Number(response.headers.get('content-length')) > MAX_ICON_BYTES) {
    await response.body?.cancel();
    return null;
  }
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let size = 0;
  for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
    size += chunk.value.byteLength;
    if (size > MAX_ICON_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(chunk.value);
  }
  return new Uint8Array(await new Blob(chunks).arrayBuffer());
}

export async function imageDataUrl(response: Response): Promise<string | null> {
  const type = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
  if (!response.ok || !type?.startsWith('image/')) return null;
  const bytes = await readLimited(response);
  if (!bytes?.length) return null;
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const dataUrl = `data:${type};base64,${btoa(binary)}`;
  return isSiteIcon(dataUrl) ? dataUrl : null;
}
