import { logDebug } from '../logger';

// Cache only: never hits the network

const MAX_ICON_BYTES = 64 * 1024;
const READ_BUDGET_MS = 300;

function iconCandidates(): string[] {
  const declared = Array.from(
    document.querySelectorAll<HTMLLinkElement>(
      'link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]',
    ),
  ).map((link) => link.href);

  return [...declared, new URL('/favicon.ico', window.location.origin).href];
}

function isSameOrigin(url: string): boolean {
  try {
    return new URL(url).origin === window.location.origin;
  } catch {
    return false;
  }
}

function toDataUrl(blob: Blob): Promise<string | null> {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : null);
    reader.onerror = () => resolve(null);
    reader.readAsDataURL(blob);
  });
}

async function readCandidate(url: string): Promise<string | null> {
  const response = await fetch(url, {
    cache: 'only-if-cached',
    mode: 'same-origin',
    credentials: 'omit',
    redirect: 'error',
  });

  if (!response.ok) return null;

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.startsWith('image/')) return null;

  const blob = await response.blob();
  if (blob.size === 0 || blob.size > MAX_ICON_BYTES) return null;

  return toDataUrl(blob);
}

async function readFirstCached(): Promise<string | null> {
  const seen = new Set<string>();

  for (const url of iconCandidates()) {
    if (!isSameOrigin(url) || seen.has(url)) continue;
    seen.add(url);

    try {
      const dataUrl = await readCandidate(url);
      if (dataUrl) return dataUrl;
    } catch {
      // Cache miss: try the next one
    }
  }

  return null;
}

export async function readCachedPageIcon(): Promise<string | null> {
  const budget = new Promise<null>((resolve) => {
    setTimeout(() => resolve(null), READ_BUDGET_MS);
  });

  try {
    return await Promise.race([readFirstCached(), budget]);
  } catch (error: unknown) {
    logDebug('[PageIcon] Cached icon lookup failed', error);
    return null;
  }
}
