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

// Hosts Nydia asked access to for renterd, one storage key each, so that a
// click records one without reading first: the prompt may close the popup
// before a read returns.
const REQUESTED_HOST = 'renterdAccess:';

// Must be called before any await in a click handler: browsers show the
// prompt only during a user gesture. Resolves to false if access is refused.
export function requestRenterdAccess(address: string): Promise<boolean> {
  const granted = browser.permissions.request({ origins: renterdOrigins(address) }).catch((error: unknown) => {
    logError('[Renterd] Permission request failed', error);
    return false;
  });
  // Recorded even if refused: removal only takes what was granted.
  browser.storage.local.set({ [REQUESTED_HOST + canonicalAddress(address)]: true }).catch((error: unknown) => {
    logError('[Renterd] Failed to record the requested server', error);
  });
  return granted;
}

// Resolves to false if access was never granted or the check failed.
export function hasRenterdAccess(address: string): Promise<boolean> {
  return browser.permissions.contains({ origins: renterdOrigins(address) }).catch((error: unknown) => {
    logError('[Renterd] Permission check failed', error);
    return false;
  });
}

// Takes back the access Nydia asked for renterd servers other than the saved
// one, or for all of them without one, so it does not pile up as the server
// changes or other addresses are tested. Access Nydia did not ask for, such as
// a site the user allowed for passkeys, is not touched. Neither is a pattern
// the manifest declares, even for a requested host: the content script needs it.
export async function keepRenterdAccessOnly(address: string | null): Promise<void> {
  try {
    const keep = address ? canonicalAddress(address) : null;
    const hosts = Object.keys(await browser.storage.local.get(null))
      .filter((key) => key.startsWith(REQUESTED_HOST))
      .map((key) => key.slice(REQUESTED_HOST.length))
      .filter((host) => host !== keep);
    if (!hosts.length) return;

    const manifest = browser.runtime.getManifest();
    const declared = new Set([
      ...(manifest.content_scripts ?? []).flatMap((script) => script.matches ?? []),
      ...(manifest.host_permissions ?? []),
    ]);
    const { origins: granted = [] } = await browser.permissions.getAll();
    const stale = hosts
      .filter((host) => RENTERD_ADDRESS.test(host))
      .flatMap(renterdOrigins)
      .filter((origin) => granted.includes(origin) && !declared.has(origin));
    // One at a time, so an origin the browser refuses does not stop the rest.
    for (const origin of stale) {
      await browser.permissions.remove({ origins: [origin] }).catch((error: unknown) => {
        logError('[Renterd] Failed to remove access to an old server', error);
      });
    }
    await browser.storage.local.remove(hosts.map((host) => REQUESTED_HOST + host));
  } catch (error: unknown) {
    logError('[Renterd] Failed to remove access to other servers', error);
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
