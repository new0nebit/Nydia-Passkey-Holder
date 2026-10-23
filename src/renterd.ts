import browser from 'browser-api';

import { logError } from './logger';
import { RenterdSettings } from './types';

// A host name or IPv4 address, without scheme, port, path or wildcards.
export const RENTERD_ADDRESS = /^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(?<!-)$/;

// Browsers report host names in lower case, so the address takes the same
// form wherever it is saved, compared or turned into origins.
export function canonicalAddress(address: string): string {
  return address.trim().toLowerCase();
}

export function renterdOrigins(address: string): string[] {
  const host = canonicalAddress(address);
  if (!RENTERD_ADDRESS.test(host)) throw new Error('Invalid renterd server address.');
  return [`http://${host}/*`, `https://${host}/*`];
}

// Must be called before any await in a click handler: browsers show the
// prompt only during a user gesture. Resolves to false if access is refused.
export function requestRenterdAccess(address: string): Promise<boolean> {
  return browser.permissions.request({ origins: renterdOrigins(address) }).catch((error: unknown) => {
    logError('[Renterd] Permission request failed', error);
    return false;
  });
}

// Resolves to false if access was never granted or the check failed.
export function hasRenterdAccess(address: string): Promise<boolean> {
  return browser.permissions.contains({ origins: renterdOrigins(address) }).catch((error: unknown) => {
    logError('[Renterd] Permission check failed', error);
    return false;
  });
}

// The pattern itself, or any host under a scheme://*/* wildcard
function inManifest(origin: string, patterns: string[]): boolean {
  return patterns.some((pattern) =>
    pattern === origin || (pattern.endsWith('://*/*') && origin.startsWith(pattern.slice(0, -'*/*'.length))));
}

// Keep manifest access needed by content scripts.
export async function removeRenterdAccess(address: string): Promise<void> {
  try {
    const manifest = browser.runtime.getManifest();
    const patterns = [
      ...(manifest.content_scripts ?? []).flatMap((script) => script.matches ?? []),
      ...(manifest.host_permissions ?? []),
    ];
    const { origins: granted = [] } = await browser.permissions.getAll();
    const stale = renterdOrigins(address).filter((origin) => granted.includes(origin) && !inManifest(origin, patterns));
    if (stale.length) await browser.permissions.remove({ origins: stale });
  } catch (error: unknown) {
    logError('[Renterd] Failed to remove access to the old server', error);
  }
}

export function noAccessMessage(address: string): string {
  return `Nydia needs access to ${address} to reach renterd.`;
}

export const WRONG_PASSWORD = 'renterd rejected the password.';

// Auto-detect protocol by trying HTTPS first, then HTTP
export async function detectProtocol(settings: RenterdSettings): Promise<'http' | 'https'> {
  const protocols: Array<'https' | 'http'> = ['https', 'http'];

  for (const protocol of protocols) {
    const url = `${protocol}://${settings.serverAddress}:${settings.serverPort}/api/worker/state`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: 'Basic ' + btoa(`username:${settings.password}`),
        },
        signal: controller.signal,
      });
    } catch {
      continue;
    } finally {
      clearTimeout(timeoutId);
    }

    if (response.ok) return protocol;
    // Authentication failed: stop here instead of trying another protocol.
    if (response.status === 401) throw new Error(WRONG_PASSWORD);
  }

  throw new Error('Failed to connect to renterd server.');
}
