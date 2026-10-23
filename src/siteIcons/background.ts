import browser from 'browser-api';

import { BackgroundMessage } from '../types';
import { canonicalRpIdForOrigin, getWebAuthnSenderOrigin, iconDomain } from '../utils/rpId';
import { isIconDataUrl } from './image';
import { iconsEnabled, markIconMissing, pruneIcons, readIcon, setIconsEnabled, writeIcon } from './storage';

const MISSING_RETRY_MS = 30 * 24 * 60 * 60 * 1000;

let pruning: Promise<void> | null = null;
let pruneAgain = false;

// After the reply, one pass at a time
function schedulePrune(): void {
  if (pruning) {
    pruneAgain = true;
    return;
  }
  pruning = (async () => {
    do {
      pruneAgain = false;
      await pruneIcons();
    } while (pruneAgain);
  })().catch(() => {}).finally(() => { pruning = null; });
}

function isMenu(sender: unknown): boolean {
  if (!sender || typeof sender !== 'object' || !('url' in sender) || typeof sender.url !== 'string') {
    return false;
  }
  try {
    const expected = new URL(browser.runtime.getURL('menu.html'));
    const actual = new URL(sender.url);
    return actual.protocol === expected.protocol && actual.host === expected.host &&
      actual.pathname === expected.pathname;
  } catch {
    return false;
  }
}

export async function handleSiteIconMessage(message: BackgroundMessage, sender: unknown): Promise<unknown> {
  const menu = isMenu(sender);
  if (message.type === 'setSiteIconsEnabled') {
    if (!menu) throw new DOMException('Only settings may change website icons', 'SecurityError');
    if (typeof message.enabled !== 'boolean') throw new Error('Invalid icon setting');
    await setIconsEnabled(message.enabled);
    return { enabled: message.enabled };
  }

  if (message.type === 'markSiteIconMissing' && !menu) {
    throw new DOMException('Only the menu may report missing icons', 'SecurityError');
  }

  if (menu && message.type === 'getSiteIcon' && message.rpId === undefined) {
    const enabled = await iconsEnabled();
    if (enabled) schedulePrune();
    return { enabled };
  }

  // Content scripts: own RP only
  const origin = menu && typeof message.rpId === 'string'
    ? `https://${message.rpId}`
    : getWebAuthnSenderOrigin(sender);
  const rpId = origin && typeof message.rpId === 'string'
    ? canonicalRpIdForOrigin(message.rpId, origin)
    : null;
  if (!rpId) throw new DOMException('Invalid website icon caller', 'SecurityError');

  if (!(await iconsEnabled())) return { enabled: false };
  if (message.type === 'getSiteIcon') {
    const entry = await readIcon(rpId);
    if (entry && 'dataUrl' in entry) return { enabled: true, dataUrl: entry.dataUrl };
    // Future date: the clock moved back
    const age = entry ? Date.now() - entry.missingSince : -1;
    // Keeps tldts out of the menu bundle
    return {
      enabled: true,
      dataUrl: null,
      missing: age >= 0 && age < MISSING_RETRY_MS,
      iconDomain: iconDomain(rpId),
    };
  }
  if (message.type === 'markSiteIconMissing') return { enabled: true, saved: await markIconMissing(rpId) };
  if (!isIconDataUrl(message.dataUrl)) throw new Error('Invalid website icon');
  return { enabled: true, saved: await writeIcon(rpId, message.dataUrl) };
}
